#!/usr/bin/env python3
"""
Migration: Add timezone support to users table
Adds a timezone column to store user's preferred timezone
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'firmware_checker.db')

def migrate():
    """Add timezone column to users table"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Check if column already exists
        cursor.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cursor.fetchall()]
        
        if 'timezone' not in columns:
            print("Adding timezone column to users table...")
            cursor.execute("""
                ALTER TABLE users ADD COLUMN timezone TEXT DEFAULT 'UTC'
            """)
            conn.commit()
            print("✓ Successfully added timezone column")
        else:
            print("✓ Timezone column already exists")
            
    except Exception as e:
        print(f"✗ Error during migration: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()

if __name__ == '__main__':
    print("=" * 80)
    print("Running migration: Add user timezone support")
    print("=" * 80)
    migrate()
    print("=" * 80)
    print("Migration complete!")
    print("=" * 80)
