const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const session = require('express-session');
const rateLimit = require('express-rate-limit');

const app = express();

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: { success: false, message: "⚠️ รอ 15 นาที" } });
const verifyLimiter = rateLimit({ windowMs: 1 * 60 * 1000, max: 20, message: { success: false, message: "⚠️ Rate Limited" } });

app.use(express.json());

// ❌ ลบการฝังรหัสผ่านตรงๆ ออกไปแล้ว!
// const ADMIN_USER = 'admin';
// const ADMIN_PASS = '1234';

app.use(session({
    secret: 'my-super-secret-key', 
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } 
}));

const db = new sqlite3.Database('./database.sqlite');

// 🌟 สร้างตาราง (เพิ่มตาราง users เข้ามาใหม่)
db.serialize(() => {
    // 🆕 ตารางเก็บผู้ใช้งาน (เข้ารหัสผ่าน)
    db.run(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE, password TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS apps (id TEXT PRIMARY KEY, name TEXT, owner_id TEXT, secret TEXT, version TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS licenses (key_string TEXT PRIMARY KEY, app_id TEXT, hwid TEXT, expires_at DATETIME, status TEXT DEFAULT 'active')`);
    db.run(`CREATE TABLE IF NOT EXISTS variables (id TEXT PRIMARY KEY, app_id TEXT, name TEXT, value TEXT)`);
});

function requireAuth(req, res, next) {
    if (req.session.loggedIn) next(); 
    else res.status(401).json({ success: false, message: 'Unauthorized' });
}

// ==========================================
// 🔐 ระบบ สมัครสมาชิก / ล็อกอิน แบบปลอดภัย (Database & Hash)
// ==========================================
app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: "กรุณากรอกข้อมูลให้ครบ" });

    const userId = uuidv4();
    // 🛡️ เข้ารหัสผ่านด้วย SHA-256 ก่อนลง Database
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');

    db.run(`INSERT INTO users (id, username, password) VALUES (?, ?, ?)`, [userId, username, hashedPassword], function(err) {
        if (err) return res.status(400).json({ success: false, message: "ชื่อผู้ใช้นี้มีคนใช้แล้ว!" });
        res.json({ success: true, message: "สมัครสมาชิกสำเร็จ!" });
    });
});

app.post('/api/login', loginLimiter, (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: "กรุณากรอกข้อมูลให้ครบ" });

    // 🛡️ นำรหัสผ่านที่กรอกมาเข้ารหัส แล้วไปเทียบกับใน Database
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');

    db.get(`SELECT * FROM users WHERE username = ? AND password = ?`, [username, hashedPassword], (err, user) => {
        if (user) { 
            req.session.loggedIn = true; 
            req.session.userId = user.id; // เก็บ Session ID ให้ปลอดภัยยิ่งขึ้น
            res.json({ success: true }); 
        } 
        else { 
            res.status(401).json({ success: false, message: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง!" }); 
        }
    });
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });

// ==========================================
// 🌟 API จัดการแอปพลิเคชัน (Admin)
// ==========================================
app.post('/api/apps/create', requireAuth, (req, res) => {
    const { name, version } = req.body;
    const appId = uuidv4();
    const ownerId = crypto.randomBytes(8).toString('hex');
    const secret = crypto.randomBytes(32).toString('hex');

    db.run(`INSERT INTO apps (id, name, owner_id, secret, version) VALUES (?, ?, ?, ?, ?)`, 
        [appId, name, ownerId, secret, version || '1.0'], () => res.json({ success: true, message: "สร้างแอปพลิเคชันสำเร็จ" }));
});
app.get('/api/apps', requireAuth, (req, res) => { db.all(`SELECT * FROM apps`, [], (err, rows) => { res.json({ success: true, apps: rows }); }); });

// ==========================================
// 🆕 API จัดการตัวแปร (Server Variables)
// ==========================================
app.get('/api/variables', requireAuth, (req, res) => { db.all(`SELECT * FROM variables WHERE app_id = ?`, [req.query.app_id], (err, rows) => { res.json({ success: true, variables: rows || [] }); }); });
app.post('/api/variables/add', requireAuth, (req, res) => { db.run(`INSERT INTO variables (id, app_id, name, value) VALUES (?, ?, ?, ?)`, [uuidv4(), req.body.app_id, req.body.name, req.body.value], () => res.json({ success: true })); });
app.post('/api/variables/delete', requireAuth, (req, res) => { db.run(`DELETE FROM variables WHERE id = ?`, [req.body.id], () => res.json({ success: true })); });

// ==========================================
// 🚀 API เช็คคีย์ของลูกค้า (อัปเกรดระบบ HMAC Signature!)
// ==========================================
app.post('/api/verify', verifyLimiter, (req, res) => {
    const { key, hwid, app_name, owner_id, version, timestamp } = req.body;
    const clientSignature = req.headers['x-signature']; 
    
    if (!key || !hwid || !app_name || !owner_id || !version || !timestamp || !clientSignature) {
        return res.status(400).json({ success: false, message: "❌ Denied: Missing data or digital signature!" });
    }

    const currentServerTime = Math.floor(Date.now() / 1000); 
    const clientTime = parseInt(timestamp);
    
    if (Math.abs(currentServerTime - clientTime) > 30) {
        console.log(`[SECURITY ALERT] Replay Attack Detected from: ${app_name}`);
        return res.status(401).json({ success: false, message: "❌ Denied: Request expired (Replay Attack Detected)" });
    }

    db.get(`SELECT * FROM apps WHERE name = ? AND owner_id = ?`, [app_name, owner_id], (err, appData) => {
        if (!appData) return res.status(401).json({ success: false, message: "Invalid Application Credentials!" });

        const dataToSign = `${key}|${hwid}|${app_name}|${owner_id}|${version}|${timestamp}`;
        const expectedSignature = crypto.createHmac('sha256', appData.secret).update(dataToSign).digest('hex');

        if (clientSignature !== expectedSignature) {
            console.log(`[SECURITY ALERT] Invalid signature from: ${app_name}`);
            return res.status(401).json({ success: false, message: "❌ Denied: Invalid Signature" });
        }

        if (appData.version !== version) return res.status(426).json({ success: false, message: `New version available (${appData.version}). Please update!` });

        db.get(`SELECT * FROM licenses WHERE key_string = ? AND app_id = ?`, [key, appData.id], (err, row) => {
            if (!row) return res.status(404).json({ success: false, message: "Key not found in the system" });
            if (row.status === 'banned') return res.status(403).json({ success: false, message: "❌ This key is banned!" });
            if (new Date() > new Date(row.expires_at)) return res.status(403).json({ success: false, message: "This key has expired" });

            db.all(`SELECT name, value FROM variables WHERE app_id = ?`, [appData.id], (err, vars) => {
                let serverVars = {};
                if (vars) vars.forEach(v => serverVars[v.name] = v.value);

                if (row.hwid === null) {
                    db.run(`UPDATE licenses SET hwid = ? WHERE key_string = ?`, [hwid, key]);
                    return res.json({ success: true, message: "First time login, HWID bound successfully ✅", variables: serverVars });
                } else if (row.hwid === hwid) {
                    return res.json({ success: true, message: "Authentication successful ✅", variables: serverVars });
                } else {
                    return res.status(403).json({ success: false, message: "Key is already used on another machine ❌" });
                }
            });
        });
    });
});

// ==========================================
// API สร้างคีย์และอื่นๆ 
// ==========================================
app.post('/api/generate-key', requireAuth, (req, res) => {
    const { prefix, days, app_id } = req.body; 
    let newKey = prefix ? `${prefix.trim()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}` : uuidv4(); 
    const expires = new Date(Date.now() + (parseInt(days) || 30) * 86400000).toISOString();
    db.run(`INSERT INTO licenses (key_string, app_id, hwid, expires_at, status) VALUES (?, ?, ?, ?, 'active')`, [newKey, app_id, null, expires], () => res.json({ success: true, message: "สร้างคีย์สำเร็จ!", key: newKey }));
});
app.get('/api/keys', requireAuth, (req, res) => { db.all(`SELECT * FROM licenses WHERE app_id = ? ORDER BY expires_at DESC`, [req.query.app_id], (err, rows) => { res.json({ success: true, keys: rows }); }); });
app.post('/api/update-status', requireAuth, (req, res) => { db.run(`UPDATE licenses SET status = ? WHERE key_string = ?`, [req.body.status, req.body.key], () => res.json({ success: true })); });
app.post('/api/delete-key', requireAuth, (req, res) => { db.run(`DELETE FROM licenses WHERE key_string = ?`, [req.body.key], () => res.json({ success: true })); });
app.post('/api/reset-hwid', requireAuth, (req, res) => { db.run(`UPDATE licenses SET hwid = NULL WHERE key_string = ?`, [req.body.key], () => res.json({ success: true })); });

// ==========================================
// 🌐 หน้าเว็บ Routing
// ==========================================
app.get('/register', (req, res) => { res.sendFile(__dirname + '/register.html'); });
app.get('/login', (req, res) => { res.sendFile(__dirname + '/login.html'); });
app.get('/admin', (req, res) => { req.session.loggedIn ? res.sendFile(__dirname + '/admin.html') : res.redirect('/login'); });
app.get('/', (req, res) => { res.redirect('/admin'); });

app.listen(3000, () => console.log(`✅ Server running on http://localhost:3000`));