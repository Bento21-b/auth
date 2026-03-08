import requests
import subprocess
import uuid
import sys
import hmac
import hashlib
import time

# ==========================================
# 🔑 APPLICATION CREDENTIALS 
# ==========================================
APP_NAME = "test"
OWNER_ID = "41eb103d0e24b378"
APP_SECRET = "5ecdf2179f9fcea93ed33eaeea1600d2455b51fe1ae405e0584fc87323b1548b"
APP_VERSION = "1.0"

API_URL = "https://precisive-meg-unalterably.ngrok-free.dev"

def get_hwid():
    try:
        return subprocess.check_output('wmic csproduct get uuid', shell=True).decode().split('\n')[1].strip()
    except:
        return str(uuid.getnode())

def verify_with_server(key, hwid):
    try:
        current_timestamp = str(int(time.time()))

        payload = {
            "key": key,
            "hwid": hwid,
            "app_name": APP_NAME,
            "owner_id": OWNER_ID,
            "version": APP_VERSION,
            "timestamp": current_timestamp
        }
        
        data_to_sign = f"{key}|{hwid}|{APP_NAME}|{OWNER_ID}|{APP_VERSION}|{current_timestamp}"
        signature = hmac.new(APP_SECRET.encode('utf-8'), data_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        
        headers = {
            "X-Signature": signature
        }
        
        response = requests.post(API_URL, json=payload, headers=headers, timeout=5)
        return response.json()
        
    except requests.exceptions.RequestException:
        return {"success": False, "message": "❌ Cannot connect to the server."}

def main():
    print(f"=== Running Application: {APP_NAME} v{APP_VERSION} ===")
    user_key = input("🔑 Please enter License Key: ")
    hwid = get_hwid()
    
    result = verify_with_server(user_key, hwid)
    
    if result.get("success"):
        print(f"\n[+] 🔓 {result.get('message')}")
        
        server_vars = result.get("variables", {})
        download_url = server_vars.get("Adhdwsh_awdwad")
        
        if download_url:
            print(f"[!] Downloading secret file from: {download_url}")
            
        print("\n[+] Starting main program...")
        
        # หยุดรอให้ผู้ใช้อ่านข้อความ ค่อยกด Enter เพื่อออก
        input("\nPress Enter to exit...")
        
    else:
        print(f"\n[-] 🔒 {result.get('message')}")
        
        # หยุดรอเวลาคีย์ผิด จะได้เห็นว่าผิดเพราะอะไร
        input("\nPress Enter to exit...")
        sys.exit()

if __name__ == "__main__":
    main()