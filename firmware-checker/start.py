#!/usr/bin/env python3
"""
Quick start script for Firmware Version Checker
This script helps you get the application running quickly
"""

import os
import sys
import subprocess
import platform

def print_banner():
    print("=" * 60)
    print("🔧 Firmware Version Checker - Quick Start")
    print("=" * 60)
    print()

def check_python_version():
    print("📋 Checking Python version...")
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        print(f"   Current version: {sys.version}")
        return False
    print(f"✅ Python {sys.version.split()[0]} - OK")
    return True

def create_virtual_environment():
    print("\n🐍 Creating virtual environment...")
    venv_name = "firmware_env"
    
    if os.path.exists(venv_name):
        print(f"✅ Virtual environment '{venv_name}' already exists")
        return True
    
    try:
        subprocess.run([sys.executable, "-m", "venv", venv_name], check=True)
        print(f"✅ Virtual environment '{venv_name}' created successfully")
        return True
    except subprocess.CalledProcessError:
        print("❌ Failed to create virtual environment")
        return False

def get_activation_command():
    if platform.system() == "Windows":
        return "firmware_env\\Scripts\\activate"
    else:
        return "source firmware_env/bin/activate"

def install_dependencies():
    print("\n📦 Installing dependencies...")
    
    # Determine pip command based on platform and virtual environment
    if platform.system() == "Windows":
        pip_cmd = "firmware_env\\Scripts\\pip"
    else:
        pip_cmd = "firmware_env/bin/pip"
    
    try:
        subprocess.run([pip_cmd, "install", "-r", "requirements.txt"], check=True)
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError:
        print("❌ Failed to install dependencies")
        print("   Try running manually: pip install -r requirements.txt")
        return False

def initialize_database():
    print("\n🗄️  Initializing database...")
    
    # Import and initialize the database
    try:
        from app import init_db
        init_db()
        print("✅ Database initialized successfully")
        return True
    except Exception as e:
        print(f"❌ Failed to initialize database: {e}")
        return False

def print_next_steps():
    activation_cmd = get_activation_command()
    
    print("\n🎉 Setup completed successfully!")
    print("\n📖 Next steps:")
    print("1. Activate the virtual environment:")
    print(f"   {activation_cmd}")
    print()
    print("2. Start the application:")
    print("   python app.py")
    print()
    print("3. Open your browser and navigate to:")
    print("   http://localhost:5000")
    print()
    print("4. Add your first system and start checking firmware!")
    print()
    print("📚 For more information, see README.md")
    print()

def main():
    print_banner()
    
    # Check system requirements
    if not check_python_version():
        sys.exit(1)
    
    # Create virtual environment
    if not create_virtual_environment():
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        sys.exit(1)
    
    # Initialize database
    if not initialize_database():
        print("⚠️  Database initialization failed, but you can try running the app anyway")
    
    # Show next steps
    print_next_steps()

if __name__ == "__main__":
    main()