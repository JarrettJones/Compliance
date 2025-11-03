#!/usr/bin/env python3
"""
Generate a secure secret key for Flask application.
Run this script and copy the output to your .env file as SECRET_KEY.
"""

import secrets

def generate_secret_key(length=32):
    """Generate a cryptographically secure secret key
    
    Args:
        length: Number of bytes for the key (default 32 = 64 hex characters)
        
    Returns:
        Hex-encoded secret key string
    """
    return secrets.token_hex(length)

if __name__ == "__main__":
    key = generate_secret_key()
    print("=" * 70)
    print("Generated Secret Key for Flask Application")
    print("=" * 70)
    print("\nCopy this key to your .env file:")
    print(f"\nSECRET_KEY={key}\n")
    print("=" * 70)
    print("\nNEVER commit this key to version control!")
    print("Keep it secure and private.")
    print("=" * 70)
