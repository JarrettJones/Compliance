#!/usr/bin/env python3
"""
Simple test script to verify Redfish connection matches PowerShell example
"""

import requests
import json
from requests.auth import HTTPBasicAuth
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_redfish_connection():
    """Test Redfish connection with exact same parameters as PowerShell"""
    
    # Exact URL from your PowerShell example
    url = "https://172.29.89.27:8080/5/redfish/v1/System"
    
    # Prompt for the same credentials you use in PowerShell
    print("Enter the same credentials you use in your PowerShell $RMcred variable")
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()
    
    if not username:
        print("No username provided. Exiting.")
        return
    if not password:
        print("No password provided. Exiting.")
        return
    
    print(f"Testing connection to: {url}")
    print(f"Using credentials: {username}/{'*' * len(password)}")
    print("-" * 50)
    
    try:
        response = requests.get(
            url,
            auth=HTTPBasicAuth(username, password),
            verify=False,  # Disable SSL verification like PowerShell TrustAllCertsPolicy
            timeout=30,
            headers={'Accept': 'application/json'}
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print("-" * 50)
        
        if response.status_code == 200:
            data = response.json()
            print("SUCCESS! Connection working.")
            print("Response data:")
            print(json.dumps(data, indent=2))
            
            # Extract key firmware versions like your PowerShell output
            print("\n" + "="*50)
            print("FIRMWARE VERSIONS FOUND:")
            print("="*50)
            
            bios_version = data.get('BiosVersion', 'Not Found')
            print(f"BIOS Version: {bios_version}")
            
            oem_data = data.get('Oem', {}).get('Microsoft', {})
            bmc_version = oem_data.get('BMCVersion', 'Not Found')
            dcscm_cpld = oem_data.get('DCSCMCPLDVersion', 'Not Found')
            cpld_version = oem_data.get('CPLDVersion', 'Not Found')
            
            print(f"BMC Version: {bmc_version}")
            print(f"DCSCM CPLD Version: {dcscm_cpld}")
            print(f"CPLD Version: {cpld_version}")
            
        else:
            print(f"FAILED! Status: {response.status_code}")
            print(f"Response: {response.text}")
            
    except requests.exceptions.SSLError as e:
        print(f"SSL Error: {e}")
        print("This might be a certificate issue.")
    except requests.exceptions.ConnectionError as e:
        print(f"Connection Error: {e}")
        print("Cannot reach the server.")
    except requests.exceptions.Timeout as e:
        print(f"Timeout Error: {e}")
        print("Server took too long to respond.")
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {e}")
    except json.JSONDecodeError as e:
        print(f"JSON Parse Error: {e}")
        print(f"Raw response: {response.text}")
    except Exception as e:
        print(f"Unexpected Error: {e}")

if __name__ == "__main__":
    test_redfish_connection()