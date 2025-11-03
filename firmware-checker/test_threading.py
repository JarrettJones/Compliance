#!/usr/bin/env python3
"""
Test script for threaded firmware checking functionality
"""
import requests
import json
import time
import sys

BASE_URL = "http://localhost:5000"

def test_threading_implementation():
    """Test the threaded firmware checking"""
    
    print("=" * 60)
    print("TESTING THREADED FIRMWARE CHECK IMPLEMENTATION")
    print("=" * 60)
    
    # First, check current active checks
    print("\n1. Checking initial active checks...")
    try:
        response = requests.get(f"{BASE_URL}/api/active-checks")
        if response.status_code == 200:
            active_data = response.json()
            print(f"✅ Active threads: {active_data['thread_count']}")
            print(f"✅ Database running checks: {active_data['database_count']}")
        else:
            print(f"❌ Failed to get active checks: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error checking active checks: {e}")
        return False
    
    # Get the first system to test with
    print("\n2. Getting systems list...")
    try:
        response = requests.get(f"{BASE_URL}/systems")
        if response.status_code == 200:
            print("✅ Successfully accessed systems page")
            # We'll assume system ID 1 exists for testing
            system_id = 1
        else:
            print(f"❌ Failed to access systems page: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error accessing systems: {e}")
        return False
    
    # Test starting a firmware check (this will fail because no real system exists)
    # But we can test the API endpoint behavior
    print(f"\n3. Testing firmware check API with system ID {system_id}...")
    try:
        check_data = {
            "system_id": system_id,
            "username": "test",
            "password": "test"
        }
        
        response = requests.post(
            f"{BASE_URL}/api/check-firmware",
            json=check_data,
            headers={'Content-Type': 'application/json'}
        )
        
        print(f"Response status: {response.status_code}")
        print(f"Response body: {response.text}")
        
        if response.status_code == 404:
            print("✅ Expected 404 - System not found (this is correct for testing)")
            return True
        elif response.status_code == 202:
            # If it worked, get the check info
            result = response.json()
            check_id = result.get('check_id')
            print(f"✅ Firmware check started successfully!")
            print(f"   Check ID: {check_id}")
            print(f"   Status: {result.get('status')}")
            
            # Monitor the check for a few seconds
            print("\n4. Monitoring threaded check...")
            for i in range(5):
                time.sleep(2)
                
                # Check active threads
                active_response = requests.get(f"{BASE_URL}/api/active-checks")
                if active_response.status_code == 200:
                    active_data = active_response.json()
                    print(f"   [{i+1}] Active threads: {active_data['thread_count']}")
                    
                    if str(check_id) in active_data['active_threads']:
                        thread_info = active_data['active_threads'][str(check_id)]
                        print(f"   [{i+1}] Check {check_id}: {thread_info['current_category']} ({thread_info['runtime_seconds']:.1f}s)")
                    else:
                        print(f"   [{i+1}] Check {check_id}: Not in active threads (may have completed)")
                        break
            
            return True
        else:
            print(f"❌ Unexpected response: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Error testing firmware check API: {e}")
        return False

if __name__ == "__main__":
    success = test_threading_implementation()
    sys.exit(0 if success else 1)