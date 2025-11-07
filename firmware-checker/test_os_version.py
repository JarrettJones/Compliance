"""
OS Version Check Test Script

Tests the OS version checker functionality both locally and remotely.

Usage:
  Local Test:  python test_os_version.py
  Remote Test: python test_os_version.py <computer_name> <username> <password>

Examples:
  python test_os_version.py
  python test_os_version.py 192.168.1.100 administrator MyPass123
  python test_os_version.py myserver.domain.com domain\\user MyPass123
"""

import sys
import os
import json
from datetime import datetime

# Add the firmware_modules directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'firmware_modules'))

from os_version import OSVersionChecker


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


def test_os_version(computer_name, username=None, password=None):
    """Test OS version collection"""
    print_section("WINDOWS OS VERSION CHECK TEST")
    
    checker = OSVersionChecker(os_username=username, os_password=password, timeout=30)
    
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
    
    # Test 3: OS Version Collection
    print_subsection("3. OS Version Collection")
    print(f"   Target: {computer_name}")
    if username:
        print(f"   Username: {username}")
        print(f"   Using WinRM authentication")
    else:
        print(f"   Using local execution")
    
    print(f"\n   Executing OS version check...")
    result = checker.get_os_version(computer_name)
    
    # Display results
    print(f"\n   Status: {result.get('status', 'unknown')}")
    print(f"   Version: {result.get('version', 'N/A')}")
    
    if result.get('status') == 'success':
        print(f"   ✓ OS Version check SUCCESSFUL")
        if 'os_info' in result:
            print(f"\n   OS Details:")
            os_info = result['os_info']
            print(f"     Product Name: {os_info.get('product_name', 'N/A')}")
            print(f"     Display Version: {os_info.get('display_version', 'N/A')}")
            print(f"     Current Build: {os_info.get('current_build', 'N/A')}")
            print(f"     Current Version: {os_info.get('current_version', 'N/A')}")
            print(f"     UBR: {os_info.get('ubr', 'N/A')}")
            print(f"     Build Branch: {os_info.get('build_branch', 'N/A')}")
            print(f"     BuildLabEx: {os_info.get('build_lab_ex', 'N/A')}")
    elif result.get('status') == 'error':
        print(f"   ✗ OS Version check FAILED")
        print(f"   Error: {result.get('error', 'Unknown error')}")
        if 'raw_output' in result:
            print(f"\n   Raw Output:")
            print(f"   {result['raw_output']}")
    else:
        print(f"   ⚠ OS Version check returned unexpected status")
    
    return result


def save_results_to_file(results, filename=None):
    """Save test results to JSON file"""
    if filename is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"os_version_test_results_{timestamp}.json"
    
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n   Results saved to: {filename}")


def main():
    """Main test execution"""
    print("\n" + "=" * 80)
    print(" WINDOWS OS VERSION CHECK TEST SUITE")
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
        print("  Local Test:  python test_os_version.py")
        print("  Remote Test: python test_os_version.py <computer_name> <username> <password>")
        print("\nExamples:")
        print("  python test_os_version.py")
        print("  python test_os_version.py 192.168.1.100 administrator MyPass123")
        print("  python test_os_version.py myserver.domain.com domain\\user MyPass123")
        return
    
    # Store all results
    all_results = {
        'test_date': datetime.now().isoformat(),
        'computer_name': computer_name,
        'username': username if username else 'local',
        'test_results': {}
    }
    
    try:
        # Test OS Version
        os_result = test_os_version(computer_name, username, password)
        all_results['test_results']['os_version'] = os_result
        
        # Summary
        print_section("TEST SUMMARY")
        
        print("\n OS Version Test:")
        if os_result and os_result.get('status') == 'success':
            print("   ✓ PASSED")
            print(f"   Version: {os_result.get('version', 'N/A')}")
        else:
            print("   ✗ FAILED")
            if os_result:
                print(f"   Error: {os_result.get('error', 'Unknown error')}")
        
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
