"""
Comprehensive WinRM Firmware Collection Test Script

Tests all WinRM-based firmware collection methods:
- MANA Driver (Windows)
- Storage Firmware (M.2 and E.1s)

This script will test:
1. Ping connectivity
2. WinRM connectivity
3. PowerShell path detection
4. Firmware data collection
5. Error handling
"""

import sys
import os
import json
from datetime import datetime

# Add the firmware_modules directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'firmware_modules'))

from mana_driver import ManaDriverChecker
from storage_firmware import StorageFirmwareChecker


def print_section(title):
    """Print a formatted section header"""
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80)


def print_subsection(title):
    """Print a formatted subsection header"""
    print("\n" + "-" * 80)
    print(f" {title}")
    print("-" * 80)


def test_mana_driver(computer_name, username=None, password=None):
    """Test MANA Driver collection"""
    print_section("MANA DRIVER (WINDOWS) TEST")
    
    checker = ManaDriverChecker(os_username=username, os_password=password, timeout=60)
    
    # Test 1: PowerShell Path Detection
    print_subsection("1. PowerShell Executable Detection")
    pwsh_path = checker.get_powershell_executable()
    print(f"   Detected PowerShell: {pwsh_path}")
    if os.path.exists(pwsh_path):
        print(f"   ✓ PowerShell executable exists at: {pwsh_path}")
    else:
        print(f"   ✗ WARNING: PowerShell not found at: {pwsh_path}")
    
    # Test 2: Ping Test
    print_subsection("2. Ping Connectivity Test")
    ping_result = checker.test_ping_ipv4(computer_name)
    if ping_result:
        print(f"   ✓ Ping successful to {computer_name}")
    else:
        print(f"   ✗ Ping FAILED to {computer_name}")
        print(f"   Cannot proceed with WinRM tests - host unreachable")
        return None
    
    # Test 3: MANA Driver Collection
    print_subsection("3. MANA Driver Version Collection")
    print(f"   Target: {computer_name}")
    if username:
        print(f"   Username: {username}")
        print(f"   Using WinRM authentication")
    else:
        print(f"   Using local execution")
    
    print(f"\n   Executing MANA driver check...")
    result = checker.get_mana_driver_version(computer_name)
    
    # Display results
    print(f"\n   Status: {result.get('status', 'unknown')}")
    print(f"   Version: {result.get('version', 'N/A')}")
    
    if result.get('status') == 'success':
        print(f"   ✓ MANA Driver check SUCCESSFUL")
        if 'device_info' in result:
            print(f"\n   Device Details:")
            device_info = result['device_info']
            for key, value in device_info.items():
                print(f"     {key}: {value}")
    elif result.get('status') == 'error':
        print(f"   ✗ MANA Driver check FAILED")
        print(f"   Error: {result.get('error', 'Unknown error')}")
    else:
        print(f"   ⚠ MANA Driver check returned unexpected status")
    
    return result


def test_storage_firmware(computer_name, username=None, password=None):
    """Test Storage Firmware collection"""
    print_section("STORAGE FIRMWARE TEST (M.2 and E.1s)")
    
    checker = StorageFirmwareChecker(os_username=username, os_password=password, timeout=90)
    
    # Test 1: PowerShell Path Detection
    print_subsection("1. PowerShell Executable Detection")
    pwsh_path = checker.get_powershell_executable()
    print(f"   Detected PowerShell: {pwsh_path}")
    if os.path.exists(pwsh_path):
        print(f"   ✓ PowerShell executable exists at: {pwsh_path}")
    else:
        print(f"   ✗ WARNING: PowerShell not found at: {pwsh_path}")
    
    # Test 2: Local Tool Check
    print_subsection("2. UpdateStorageFirmware.exe Check")
    print(f"   Tool Path: {checker.local_exe_path}")
    if os.path.exists(checker.local_exe_path):
        print(f"   ✓ UpdateStorageFirmware.exe found")
    else:
        print(f"   ✗ WARNING: UpdateStorageFirmware.exe NOT found")
        print(f"   Storage firmware checks may fail")
    
    # Test 3: Ping Test
    print_subsection("3. Ping Connectivity Test")
    ping_result = checker.test_ping_ipv4(computer_name)
    if ping_result:
        print(f"   ✓ Ping successful to {computer_name}")
    else:
        print(f"   ✗ Ping FAILED to {computer_name}")
        print(f"   Cannot proceed with WinRM tests - host unreachable")
        return None
    
    # Test 4: Storage Firmware Collection
    print_subsection("4. Storage Firmware Collection")
    print(f"   Target: {computer_name}")
    if username:
        print(f"   Username: {username}")
        print(f"   Using WinRM authentication")
    else:
        print(f"   Using local execution")
    
    print(f"\n   Executing storage firmware check...")
    result = checker.check_storage_firmware(computer_name)
    
    # Display results
    print(f"\n   Status: {result.get('status', 'unknown')}")
    
    if result.get('status') == 'success':
        print(f"   ✓ Storage firmware check SUCCESSFUL")
        devices = result.get('storage_devices', {})
        print(f"   Total devices found: {len(devices)}")
        
        if devices:
            print(f"\n   Storage Devices:")
            for device_id, device_info in devices.items():
                print(f"\n     {device_id}:")
                print(f"       Type: {device_info.get('device_type', 'Unknown')} "
                      f"({device_info.get('device_type_hw', 'Unknown')})")
                print(f"       Vendor/Product: {device_info.get('vendor_product', 'Unknown')}")
                print(f"       Firmware: {device_info.get('firmware_version', 'Unknown')}")
                print(f"       Serial: {device_info.get('serial_number', 'Unknown')}")
                print(f"       Bus Type: {device_info.get('bus_type', 'Unknown')}")
    elif result.get('status') == 'error':
        print(f"   ✗ Storage firmware check FAILED")
        print(f"   Error: {result.get('error', 'Unknown error')}")
    else:
        print(f"   ⚠ Storage firmware check returned unexpected status")
    
    # Test 5: M.2 Device Extraction
    print_subsection("5. M.2 Device Extraction")
    m2_result = checker.get_m2_devices(computer_name)
    print(f"   Status: {m2_result.get('status', 'unknown')}")
    print(f"   Version: {m2_result.get('version', 'N/A')}")
    if m2_result.get('device_info'):
        device_count = m2_result['device_info'].get('device_count', 0)
        print(f"   M.2 Device Count: {device_count}")
    
    # Test 6: E.1s Device Extraction
    print_subsection("6. E.1s Device Extraction")
    e1s_result = checker.get_e1s_devices(computer_name)
    print(f"   Status: {e1s_result.get('status', 'unknown')}")
    print(f"   Version: {e1s_result.get('version', 'N/A')}")
    if e1s_result.get('device_info'):
        device_count = e1s_result['device_info'].get('device_count', 0)
        print(f"   E.1s Device Count: {device_count}")
    
    return {
        'full_check': result,
        'm2_devices': m2_result,
        'e1s_devices': e1s_result
    }


def save_results_to_file(results, filename=None):
    """Save test results to JSON file"""
    if filename is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"winrm_test_results_{timestamp}.json"
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n   Results saved to: {filename}")


def main():
    """Main test execution"""
    print("\n" + "=" * 80)
    print(" WinRM FIRMWARE COLLECTION TEST SUITE")
    print("=" * 80)
    print(f" Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    
    # Parse command line arguments
    if len(sys.argv) == 1:
        # No arguments - test locally
        print("\n[INFO] No arguments provided - testing LOCAL machine")
        computer_name = 'localhost'
        username = None
        password = None
    elif len(sys.argv) == 4:
        # Remote testing with credentials
        computer_name = sys.argv[1]
        username = sys.argv[2]
        password = sys.argv[3]
        print(f"\n[INFO] Testing REMOTE machine: {computer_name}")
        print(f"[INFO] Username: {username}")
    else:
        print("\nUsage:")
        print("  Local Test:  python test_winrm_collection.py")
        print("  Remote Test: python test_winrm_collection.py <computer_name> <username> <password>")
        print("\nExamples:")
        print("  python test_winrm_collection.py")
        print("  python test_winrm_collection.py 192.168.1.100 administrator MyPass123")
        print("  python test_winrm_collection.py myserver.domain.com domain\\user MyPass123")
        return
    
    # Store all results
    all_results = {
        'test_date': datetime.now().isoformat(),
        'computer_name': computer_name,
        'username': username if username else 'local',
        'tests': {}
    }
    
    try:
        # Test 1: MANA Driver
        mana_result = test_mana_driver(computer_name, username, password)
        all_results['tests']['mana_driver'] = mana_result
        
        # Test 2: Storage Firmware
        storage_result = test_storage_firmware(computer_name, username, password)
        all_results['tests']['storage_firmware'] = storage_result
        
        # Summary
        print_section("TEST SUMMARY")
        
        print("\n MANA Driver Test:")
        if mana_result and mana_result.get('status') == 'success':
            print("   ✓ PASSED")
        else:
            print("   ✗ FAILED")
        
        print("\n Storage Firmware Test:")
        if storage_result and storage_result['full_check'].get('status') == 'success':
            print("   ✓ PASSED")
        else:
            print("   ✗ FAILED")
        
        # Save results
        print_subsection("Saving Results")
        save_results_to_file(all_results)
        
        print("\n" + "=" * 80)
        print(" TEST SUITE COMPLETED")
        print("=" * 80 + "\n")
        
    except KeyboardInterrupt:
        print("\n\n[INFO] Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n[ERROR] Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
