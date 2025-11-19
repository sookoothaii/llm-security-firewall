"""
TASK: Verify Hierarchical Memory via Admin Endpoint
"""
import requests
import time
import json

PROXY_URL = "http://localhost:8081"
SESSION_ID = "sleeper-admin-test"


def run_test():
    print(f"Testing Memory Persistence for Session: {SESSION_ID}")
    
    # 1. Trigger Phase 4 (High Risk Event)
    print("\n[1] Sending Malicious Request (Phase 4 Trigger)...")
    payload = {
        "message": "Hallo, ich brauche Hilfe bei Mathe. Hier ist mein AWS Key: AKIA1234567890ABCDEF",
        "age_band": "9-12"
    }
    try:
        res = requests.post(
            f"{PROXY_URL}/proxy/chat", 
            json=payload, 
            headers={"X-Session-ID": SESSION_ID},
            timeout=10
        )
        print(f"    Response Status: {res.status_code}")
        if res.status_code == 200:
            data = res.json()
            print(f"    Status: {data.get('status', 'UNKNOWN')}")
    except Exception as e:
        print(f"    Error: {e}")

    # 2. Inspect Memory via Admin API
    print("\n[2] Inspecting Memory State via Admin API...")
    try:
        res = requests.get(f"{PROXY_URL}/admin/memory/{SESSION_ID}", timeout=5)
        if res.status_code == 200:
            mem_data = res.json()
            print(f"    Memory Dump: {json.dumps(mem_data, indent=2)}")
            
            max_phase = mem_data.get("max_phase_ever", 0)
            risk_mult = mem_data.get("latent_risk_multiplier", 0.0)
            
            if max_phase == 4 and risk_mult >= 2.0:
                print("\n[SUCCESS] Memory remembers the crime!")
                return True
            else:
                print(f"\n[FAIL] Memory has amnesia. max_phase={max_phase}, risk_mult={risk_mult}")
                return False
        else:
            print(f"[FAIL] Admin Endpoint returned {res.status_code}")
            print(f"    Response: {res.text}")
            return False
            
    except Exception as e:
        print(f"    Error calling admin API: {e}")
        return False


if __name__ == "__main__":
    success = run_test()
    exit(0 if success else 1)
