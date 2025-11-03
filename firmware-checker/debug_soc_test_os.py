#!/usr/bin/env python3
"""
Debug script for SOC Test OS functionality
Run this to see exactly what output is being received from the SSH serial session
"""

import sys
import logging
from firmware_modules.ovl2 import OVL2Checker

# Set up detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

def debug_soc_test_os():
    """Debug the SOC Test OS functionality"""
    
    print("SOC Test OS Debug Script")
    print("=" * 50)
    
    # Get connection details from user
    rscm_ip = input("Enter RSCM IP address: ").strip()
    if not rscm_ip:
        rscm_ip = "172.29.89.27"  # Default for testing
        
    system_port = input("Enter system port (default 5): ").strip()
    if not system_port:
        system_port = 5
    else:
        system_port = int(system_port)
        
    username = input("Enter username (default admin): ").strip()
    if not username:
        username = "admin"
        
    password = input("Enter password (default admin): ").strip() 
    if not password:
        password = "admin"
    
    print(f"\nTesting SOC Test OS with:")
    print(f"  RSCM IP: {rscm_ip}")
    print(f"  System Port: {system_port}")
    print(f"  Username: {username}")
    print(f"  Password: {'*' * len(password)}")
    print()
    
    # Create OVL2 checker
    checker = OVL2Checker(username=username, password=password)
    
    # Run the SOC Test OS check
    print("Running SOC Test OS check...")
    result = checker.check_soc_test_os(rscm_ip, system_port)
    
    print("\nResult:")
    print("=" * 30)
    for key, value in result.items():
        if key == 'raw_output' and value:
            print(f"{key}: (showing first 500 chars)")
            print(f"    {repr(value[:500])}")
            if len(value) > 500:
                print(f"    ... ({len(value) - 500} more characters)")
        else:
            print(f"{key}: {value}")
    
    # If there's raw output, let's also show it line by line
    if 'raw_output' in result and result['raw_output']:
        print(f"\nRaw output line by line:")
        print("-" * 30)
        lines = result['raw_output'].split('\n')
        for i, line in enumerate(lines[:20]):  # Show first 20 lines
            print(f"Line {i:2d}: {repr(line)}")
        if len(lines) > 20:
            print(f"... ({len(lines) - 20} more lines)")

if __name__ == "__main__":
    try:
        debug_soc_test_os()
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()