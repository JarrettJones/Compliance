#!/usr/bin/env python3
"""
Install CA-Signed SSL Certificate for Firmware Checker
Run this script after downloading your certificate from SSLAdmin
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

# Certificate details
CERT_THUMBPRINT = "A8A8C64E7AD375981BCE879DE6F42A42E4297515"
SERVER_NAME = "dca20301103n414.redmond.corp.microsoft.com"

# Try to find nginx installation
NGINX_PATHS = [
    r"C:\nginx-1.24.0",
    r"C:\nginx",
    r"C:\Program Files\nginx",
    r"C:\tools\nginx"
]

NGINX_PATH = None
for path in NGINX_PATHS:
    if os.path.exists(path):
        NGINX_PATH = path
        break

if not NGINX_PATH:
    # Ask user for nginx path
    pass  # Will be handled in main()

CERT_DIR = os.path.join(NGINX_PATH, "ssl") if NGINX_PATH else None

def print_colored(text, color="white"):
    """Print colored text (limited colors for Windows)"""
    colors = {
        "cyan": "\033[96m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "red": "\033[91m",
        "reset": "\033[0m"
    }
    print(f"{colors.get(color, '')}{text}{colors['reset']}")

def run_command(cmd, shell=True, capture_output=True):
    """Run a shell command and return the result"""
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=capture_output, text=True)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def main():
    print_colored("=" * 50, "cyan")
    print_colored("SSL Certificate Installation Script", "cyan")
    print_colored("=" * 50, "cyan")
    print()
    
    print_colored("Certificate Details:", "yellow")
    print(f"  Subject: {SERVER_NAME}")
    print(f"  Thumbprint: {CERT_THUMBPRINT}")
    print(f"  Expires: 12 November 2026")
    print()
    
    # Check if nginx directory exists
    global NGINX_PATH, CERT_DIR
    
    if not NGINX_PATH or not os.path.exists(NGINX_PATH):
        print_colored("nginx directory not found in default locations.", "yellow")
        print("Please enter the path to your nginx installation:")
        nginx_input = input("nginx path: ").strip().strip('"')
        
        if not os.path.exists(nginx_input):
            print_colored(f"ERROR: nginx directory not found at {nginx_input}", "red")
            sys.exit(1)
        
        NGINX_PATH = nginx_input
        CERT_DIR = os.path.join(NGINX_PATH, "ssl")
    
    print_colored(f"Using nginx directory: {NGINX_PATH}", "green")
    print()
    
    # Create ssl directory if it doesn't exist
    if not os.path.exists(CERT_DIR):
        print_colored("Creating SSL directory...", "green")
        os.makedirs(CERT_DIR, exist_ok=True)
    
    print_colored("Please download the certificate files from SSLAdmin:", "yellow")
    print("  1. Full Certificate Chain (.p7b)")
    print("  2. Base64 Encoded (.cer)")
    print()
    print_colored("Recommended: Download the Base64 Encoded (.cer) file", "green")
    print()
    
    # Prompt for certificate file location
    print_colored("Enter the path to your downloaded certificate file:", "cyan")
    print("(Drag and drop the file here, or paste the full path)")
    cert_file = input("Certificate file path: ").strip().strip('"')
    
    if not os.path.exists(cert_file):
        print_colored(f"ERROR: Certificate file not found: {cert_file}", "red")
        sys.exit(1)
    
    cert_extension = os.path.splitext(cert_file)[1].lower()
    print()
    print_colored(f"Processing certificate file: {cert_file}", "green")
    
    cert_pem_path = os.path.join(CERT_DIR, "server.crt")
    key_pem_path = os.path.join(CERT_DIR, "server.key")
    
    # Step 1: Handle different certificate formats
    print()
    print_colored("Step 1: Processing certificate...", "cyan")
    
    if cert_extension == ".cer":
        # Base64 encoded certificate - easiest option
        print("Processing Base64 encoded certificate...")
        
        # Just copy the .cer file to server.crt
        shutil.copy2(cert_file, cert_pem_path)
        print_colored("✓ Certificate copied to nginx directory", "green")
        
    elif cert_extension == ".p7b":
        # PKCS#7 certificate chain - need to convert
        print("Processing PKCS#7 certificate chain...")
        
        # Find OpenSSL
        openssl_paths = [
            r"C:\Program Files\Git\usr\bin\openssl.exe",
            r"C:\Program Files\OpenSSL\bin\openssl.exe",
            r"C:\OpenSSL-Win64\bin\openssl.exe"
        ]
        
        openssl_path = None
        for path in openssl_paths:
            if os.path.exists(path):
                openssl_path = path
                break
        
        if not openssl_path:
            print_colored("ERROR: OpenSSL not found. Please install one of:", "red")
            print("  - Git for Windows (includes OpenSSL): https://git-scm.com/download/win")
            print("  - OpenSSL for Windows: https://slproweb.com/products/Win32OpenSSL.html")
            sys.exit(1)
        
        # Convert P7B to PEM format
        cmd = f'"{openssl_path}" pkcs7 -print_certs -in "{cert_file}" -out "{cert_pem_path}"'
        success, stdout, stderr = run_command(cmd)
        
        if not success:
            print_colored(f"ERROR converting P7B: {stderr}", "red")
            sys.exit(1)
        
        print_colored("✓ Converted P7B to PEM format", "green")
    else:
        print_colored("ERROR: Unsupported certificate format. Please use .cer or .p7b", "red")
        sys.exit(1)
    
    print()
    print_colored("Step 2: Checking for private key...", "cyan")
    
    # Check if private key already exists (from CSR generation)
    if os.path.exists(key_pem_path):
        print_colored(f"✓ Private key found: {key_pem_path}", "green")
    else:
        print_colored("WARNING: Private key not found!", "yellow")
        print("The private key should have been created when you generated the CSR.")
        print(f"Please locate your private key file and copy it to: {key_pem_path}")
        print()
        
        key_input = input("Enter the path to your private key file (or press Enter to skip): ").strip().strip('"')
        if key_input and os.path.exists(key_input):
            shutil.copy2(key_input, key_pem_path)
            print_colored("✓ Private key copied", "green")
        else:
            print_colored("ERROR: Cannot proceed without private key", "red")
            sys.exit(1)
    
    print()
    print_colored("Step 3: Verifying certificate files...", "cyan")
    
    if os.path.exists(cert_pem_path) and os.path.exists(key_pem_path):
        print_colored(f"✓ Certificate file: {cert_pem_path}", "green")
        print_colored(f"✓ Private key file: {key_pem_path}", "green")
        
        # Try to display certificate info
        openssl_path = None
        for path in [r"C:\Program Files\Git\usr\bin\openssl.exe", r"C:\Program Files\OpenSSL\bin\openssl.exe"]:
            if os.path.exists(path):
                openssl_path = path
                break
        
        if openssl_path:
            print()
            print_colored("Certificate Information:", "yellow")
            cmd = f'"{openssl_path}" x509 -in "{cert_pem_path}" -noout -subject -issuer -dates'
            success, stdout, stderr = run_command(cmd)
            if success and stdout:
                print(stdout)
    else:
        print_colored("ERROR: Certificate files not created successfully", "red")
        sys.exit(1)
    
    print()
    print_colored("=" * 50, "green")
    print_colored("Certificate Installation Complete!", "green")
    print_colored("=" * 50, "green")
    print()
    print_colored("Next steps:", "yellow")
    print(f"  1. Restart nginx: cd {NGINX_PATH}; .\\nginx.exe -s reload")
    print(f"  2. Test HTTPS: https://{SERVER_NAME}/firmware-checker")
    print()
    print_colored("Files created:", "cyan")
    print(f"  Certificate: {cert_pem_path}")
    print(f"  Private Key: {key_pem_path}")
    print()

if __name__ == "__main__":
    main()
