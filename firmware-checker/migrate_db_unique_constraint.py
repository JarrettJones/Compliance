"""
Database Migration Script: Update UNIQUE constraint for systems table
Changes: name UNIQUE -> UNIQUE(name, rscm_ip, rscm_port)

This allows multiple systems with the same serial number at different RSCM locations.
"""

import sqlite3
import os
import shutil
from datetime import datetime

def migrate_database(db_path='firmware_checker.db'):
    """Migrate the systems table to use composite unique constraint"""
    
    # Backup the database first
    backup_path = f"{db_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    print(f"Creating backup: {backup_path}")
    shutil.copy2(db_path, backup_path)
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        print("Starting migration...")
        
        # Check if we need to migrate
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='systems'")
        current_schema = cursor.fetchone()
        
        if current_schema and 'UNIQUE(name, rscm_ip, rscm_port)' in current_schema['sql']:
            print("Database already migrated. No changes needed.")
            return
        
        print("Current schema needs migration...")
        
        # Get all existing data
        cursor.execute("SELECT * FROM systems")
        existing_systems = cursor.fetchall()
        print(f"Found {len(existing_systems)} existing systems")
        
        # Create new table with updated schema
        print("Creating new systems table with composite unique constraint...")
        cursor.execute('''
            CREATE TABLE systems_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                rscm_ip TEXT NOT NULL,
                rscm_port INTEGER NOT NULL DEFAULT 22,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(name, rscm_ip, rscm_port)
            )
        ''')
        
        # Copy data to new table
        print("Copying data to new table...")
        for system in existing_systems:
            try:
                cursor.execute('''
                    INSERT INTO systems_new (id, name, rscm_ip, rscm_port, description, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    system['id'],
                    system['name'],
                    system['rscm_ip'],
                    system['rscm_port'],
                    system['description'],
                    system['created_at'],
                    system['updated_at']
                ))
            except sqlite3.IntegrityError as e:
                print(f"  WARNING: Skipping duplicate system - ID: {system['id']}, "
                      f"Name: {system['name']}, RSCM: {system['rscm_ip']}:{system['rscm_port']}")
                print(f"  Error: {e}")
        
        # Drop old table and rename new one
        print("Replacing old table with new one...")
        cursor.execute("DROP TABLE systems")
        cursor.execute("ALTER TABLE systems_new RENAME TO systems")
        
        conn.commit()
        print("Migration completed successfully!")
        print(f"Backup saved at: {backup_path}")
        
    except Exception as e:
        print(f"Migration failed: {e}")
        conn.rollback()
        print("Database rolled back. Backup is still available.")
        raise
    
    finally:
        conn.close()

if __name__ == "__main__":
    db_path = 'firmware_checker.db'
    
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        print("No migration needed - new database will be created with correct schema.")
    else:
        print("=" * 60)
        print("Database Migration: Systems Table Unique Constraint")
        print("=" * 60)
        print()
        print("This will update the systems table to allow duplicate serial numbers")
        print("at different RSCM locations (different IP or port).")
        print()
        
        response = input("Continue with migration? (yes/no): ")
        if response.lower() in ['yes', 'y']:
            migrate_database(db_path)
        else:
            print("Migration cancelled.")
