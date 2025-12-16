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
                ALTER TABLE users ADD COLUMN timezone TEXT DEFAULT 'America/Los_Angeles'
            """)
            conn.commit()
            print("✓ Successfully added timezone column with default PST/PDT (America/Los_Angeles)")
            
            # Update existing users to PST/PDT
            cursor.execute("""
                UPDATE users SET timezone = 'America/Los_Angeles' WHERE timezone IS NULL OR timezone = 'UTC'
            """)
            conn.commit()
            updated_count = cursor.rowcount
            print(f"✓ Updated {updated_count} existing user(s) to PST/PDT timezone")
        else:
            print("✓ Timezone column already exists")
            
            # Update users still on UTC to PST/PDT
            cursor.execute("""
                UPDATE users SET timezone = 'America/Los_Angeles' WHERE timezone = 'UTC'
            """)
            conn.commit()
            if cursor.rowcount > 0:
                print(f"✓ Updated {cursor.rowcount} user(s) from UTC to PST/PDT")
            
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
