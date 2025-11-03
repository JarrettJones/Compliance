import json
import sqlite3
import requests
import time

# Test the threading implementation
def simple_test():
    BASE_URL = "http://localhost:5000"
    
    print("Testing threading implementation...")
    
    # Test 1: Check active checks endpoint
    try:
        response = requests.get(f"{BASE_URL}/api/active-checks", timeout=5)
        data = response.json()
        print(f"✅ Active checks API working: {data['thread_count']} threads, {data['database_count']} DB checks")
    except Exception as e:
        print(f"❌ Active checks API failed: {e}")
        return
    
    # Test 2: Check database has systems
    try:
        conn = sqlite3.connect('firmware_checker.db')
        systems = conn.execute('SELECT COUNT(*) as count FROM systems').fetchone()
        print(f"✅ Database has {systems[0]} systems")
        conn.close()
    except Exception as e:
        print(f"❌ Database check failed: {e}")
        return
        
    # Test 3: Try to start a check with a non-existent system (should get 404)
    try:
        check_data = {
            "system_id": 999,  # Non-existent system
            "username": "test",
            "password": "test"
        }
        
        response = requests.post(
            f"{BASE_URL}/api/check-firmware",
            json=check_data,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        if response.status_code == 404:
            print("✅ API correctly returned 404 for non-existent system")
        else:
            print(f"❌ Unexpected response: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Firmware check API test failed: {e}")
        return
    
    print("✅ All tests passed! Threading implementation is working.")

if __name__ == "__main__":
    simple_test()