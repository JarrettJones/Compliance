#!/usr/bin/env python3
"""
Database backup script for Firmware Checker application.
Creates timestamped backups of the SQLite database.
"""
import shutil
import os
from datetime import datetime

# Database file path
DB_FILE = 'firmware_checker.db'
BACKUP_DIR = 'backups'

def backup_database():
    """Create a timestamped backup of the database"""
    
    # Check if database exists
    if not os.path.exists(DB_FILE):
        print(f"❌ Error: Database file '{DB_FILE}' not found!")
        return False
    
    # Create backup directory if it doesn't exist
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
        print(f"✅ Created backup directory: {BACKUP_DIR}")
    
    # Generate timestamp for backup filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_filename = f'firmware_checker_{timestamp}.db'
    backup_path = os.path.join(BACKUP_DIR, backup_filename)
    
    try:
        # Copy the database file
        shutil.copy2(DB_FILE, backup_path)
        
        # Get file size for confirmation
        file_size = os.path.getsize(backup_path)
        file_size_mb = file_size / (1024 * 1024)
        
        print(f"✅ Database backed up successfully!")
        print(f"   Backup file: {backup_path}")
        print(f"   Size: {file_size_mb:.2f} MB")
        
        # List all backups
        list_backups()
        
        return True
        
    except Exception as e:
        print(f"❌ Error backing up database: {str(e)}")
        return False

def list_backups():
    """List all existing backups"""
    if not os.path.exists(BACKUP_DIR):
        print(f"\nNo backups found. Backup directory '{BACKUP_DIR}' does not exist.")
        return
    
    backups = sorted([f for f in os.listdir(BACKUP_DIR) if f.endswith('.db')])
    
    if not backups:
        print(f"\nNo backups found in '{BACKUP_DIR}'.")
        return
    
    print(f"\n📁 All backups in '{BACKUP_DIR}':")
    total_size = 0
    for backup in backups:
        backup_path = os.path.join(BACKUP_DIR, backup)
        size = os.path.getsize(backup_path)
        size_mb = size / (1024 * 1024)
        total_size += size
        modified_time = datetime.fromtimestamp(os.path.getmtime(backup_path))
        print(f"   {backup} - {size_mb:.2f} MB - {modified_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    total_size_mb = total_size / (1024 * 1024)
    print(f"\n   Total: {len(backups)} backup(s), {total_size_mb:.2f} MB")

def clean_old_backups(keep_count=10):
    """Keep only the most recent N backups"""
    if not os.path.exists(BACKUP_DIR):
        return
    
    backups = sorted([f for f in os.listdir(BACKUP_DIR) if f.endswith('.db')])
    
    if len(backups) <= keep_count:
        return
    
    # Delete oldest backups
    backups_to_delete = backups[:-keep_count]
    print(f"\n🗑️  Cleaning old backups (keeping {keep_count} most recent)...")
    
    for backup in backups_to_delete:
        backup_path = os.path.join(BACKUP_DIR, backup)
        try:
            os.remove(backup_path)
            print(f"   Deleted: {backup}")
        except Exception as e:
            print(f"   Error deleting {backup}: {str(e)}")

if __name__ == '__main__':
    import sys
    
    print("=" * 70)
    print("FIRMWARE CHECKER - DATABASE BACKUP")
    print("=" * 70)
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == 'list':
            list_backups()
            sys.exit(0)
        elif sys.argv[1] == 'clean':
            keep = int(sys.argv[2]) if len(sys.argv) > 2 else 10
            clean_old_backups(keep)
            list_backups()
            sys.exit(0)
    
    # Perform backup
    if backup_database():
        # Optionally clean old backups (keep last 10)
        clean_old_backups(keep_count=10)
        print("\n✅ Backup completed successfully!")
    else:
        print("\n❌ Backup failed!")
        sys.exit(1)
