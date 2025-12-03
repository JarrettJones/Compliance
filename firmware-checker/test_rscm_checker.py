"""
Test script for RSCM firmware checker
"""

import sys
import getpass
from firmware_modules.rscm import RSCMChecker

# Test RSCM IP and port
RSCM_IP = '172.29.131.23'
RSCM_PORT = 8080
USERNAME = 'root'

def test_rscm_checker():
    """Test RSCM firmware checker"""
    print("="*80)
    print("RSCM Firmware Checker Test")
    print("="*80)
    print(f"Target: {RSCM_IP}:{RSCM_PORT}")
    print(f"Username: {USERNAME}")
    print()
    
    # Prompt for password securely
    password = getpass.getpass(f"Enter password for {USERNAME}: ")
    if not password:
        print("✗ Password is required. Exiting.")
        return False
    print()
    
    # Initialize checker
    print("Initializing RSCM checker...")
    checker = RSCMChecker(username=USERNAME, password=password, timeout=30)
    print("✓ RSCM checker initialized\n")
    
    # Test connection
    print("Testing connection...")
    connection_result = checker.test_connection(RSCM_IP, RSCM_PORT)
    print(f"Connection Status: {connection_result['status']}")
    print(f"Message: {connection_result['message']}\n")
    
    if connection_result['status'] != 'success':
        print("✗ Connection failed. Exiting test.")
        return False
    
    # Check firmware
    print("Checking RSCM firmware...")
    print("-"*80)
    firmware_results = checker.check_firmware(RSCM_IP, RSCM_PORT)
    
    # Display results
    print("\nRSCM Firmware Check Results:")
    print("="*80)
    print(f"Status: {firmware_results['status']}")
    print(f"Timestamp: {firmware_results['timestamp']}")
    print()
    
    if firmware_results.get('errors'):
        print("Errors:")
        for error in firmware_results['errors']:
            print(f"  ✗ {error}")
        print()
    
    if firmware_results['firmware_versions']:
        print("Firmware Versions:")
        for fw_name, fw_info in firmware_results['firmware_versions'].items():
            version = fw_info.get('version', 'N/A')
            status = fw_info.get('status', 'unknown')
            symbol = "✓" if status == 'success' else "✗"
            print(f"  {symbol} {fw_name}: {version} [{status}]")
    else:
        print("  No firmware versions retrieved")
    
    print("\n" + "="*80)
    print("Test completed!")
    
    return firmware_results['status'] == 'completed'

if __name__ == '__main__':
    success = test_rscm_checker()
    sys.exit(0 if success else 1)
