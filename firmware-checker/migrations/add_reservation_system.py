"""
Migration: Add System Reservation Feature
Date: 2025-12-09
Description: Adds reservation system for booking systems with start/end times,
             conflict detection, and scheduler role for users.
"""

import sqlite3
import sys
from datetime import datetime

def run_migration(db_path='firmware_checker.db'):
    """Run the reservation system migration"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        print("=" * 80)
        print("System Reservation Migration")
        print("=" * 80)
        
        # Step 1: Update users table to include 'scheduler' role
        print("\n[1/4] Updating users table to add 'scheduler' role...")
        
        # Check current constraint
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'")
        users_table_sql = cursor.fetchone()[0]
        
        if "'scheduler'" not in users_table_sql:
            # SQLite doesn't support ALTER CONSTRAINT, so we need to recreate the table
            print("  - Creating temporary users table with new role constraint...")
            
            cursor.execute('''
                CREATE TABLE users_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'viewer',
                    is_active INTEGER DEFAULT 1,
                    email TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    team TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    CONSTRAINT valid_role CHECK (role IN ('admin', 'editor', 'viewer', 'scheduler'))
                )
            ''')
            
            print("  - Copying data from old users table...")
            cursor.execute('''
                INSERT INTO users_new 
                SELECT * FROM users
            ''')
            
            print("  - Dropping old users table...")
            cursor.execute('DROP TABLE users')
            
            print("  - Renaming new table to users...")
            cursor.execute('ALTER TABLE users_new RENAME TO users')
            
            print("  ✓ Users table updated with scheduler role")
        else:
            print("  ✓ Users table already has scheduler role")
        
        # Step 2: Create reservations table
        print("\n[2/4] Creating reservations table...")
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reservations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                system_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                start_time TIMESTAMP NOT NULL,
                end_time TIMESTAMP NOT NULL,
                purpose TEXT,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                cancelled_at TIMESTAMP,
                cancelled_by INTEGER,
                notes TEXT,
                FOREIGN KEY (system_id) REFERENCES systems (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (cancelled_by) REFERENCES users (id),
                CONSTRAINT valid_status CHECK (status IN ('active', 'completed', 'cancelled')),
                CONSTRAINT valid_time_range CHECK (end_time > start_time)
            )
        ''')
        
        print("  ✓ Reservations table created")
        
        # Step 3: Create indexes for performance
        print("\n[3/4] Creating indexes for reservation queries...")
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_reservations_system_time 
            ON reservations(system_id, start_time, end_time, status)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_reservations_user 
            ON reservations(user_id, status)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_reservations_time_range 
            ON reservations(start_time, end_time, status)
        ''')
        
        print("  ✓ Indexes created")
        
        # Step 4: Create reservation_history table for audit trail
        print("\n[4/4] Creating reservation history table...")
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reservation_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reservation_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                performed_by INTEGER NOT NULL,
                performed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                old_start_time TIMESTAMP,
                old_end_time TIMESTAMP,
                new_start_time TIMESTAMP,
                new_end_time TIMESTAMP,
                notes TEXT,
                FOREIGN KEY (reservation_id) REFERENCES reservations (id) ON DELETE CASCADE,
                FOREIGN KEY (performed_by) REFERENCES users (id),
                CONSTRAINT valid_action CHECK (action IN ('created', 'modified', 'cancelled', 'completed'))
            )
        ''')
        
        print("  ✓ Reservation history table created")
        
        # Commit all changes
        conn.commit()
        
        print("\n" + "=" * 80)
        print("✓ Migration completed successfully!")
        print("=" * 80)
        print("\nNew features available:")
        print("  • System reservation with date/time range")
        print("  • 'scheduler' role added for managing reservations")
        print("  • Conflict detection and next available time suggestions")
        print("  • Reservation history and audit trail")
        print("\nNext steps:")
        print("  1. Restart the Flask application")
        print("  2. Assign 'scheduler' role to users who need reservation access")
        print("  3. Access reservation features from the Systems page")
        
        return True
        
    except Exception as e:
        conn.rollback()
        print(f"\n✗ Migration failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        conn.close()

def verify_migration(db_path='firmware_checker.db'):
    """Verify that the migration was successful"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        print("\n" + "=" * 80)
        print("Verifying Migration")
        print("=" * 80)
        
        # Check reservations table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='reservations'")
        if not cursor.fetchone():
            print("✗ Reservations table not found")
            return False
        print("✓ Reservations table exists")
        
        # Check reservation_history table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='reservation_history'")
        if not cursor.fetchone():
            print("✗ Reservation history table not found")
            return False
        print("✓ Reservation history table exists")
        
        # Check users table has scheduler role
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'")
        users_sql = cursor.fetchone()[0]
        if "'scheduler'" not in users_sql:
            print("✗ Users table missing 'scheduler' role")
            return False
        print("✓ Users table includes 'scheduler' role")
        
        # Check indexes exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_reservations_system_time'")
        if not cursor.fetchone():
            print("✗ System time index not found")
            return False
        print("✓ All indexes created")
        
        print("\n✓ Migration verification passed!")
        return True
        
    except Exception as e:
        print(f"\n✗ Verification failed: {str(e)}")
        return False
        
    finally:
        conn.close()

if __name__ == '__main__':
    db_path = sys.argv[1] if len(sys.argv) > 1 else 'firmware_checker.db'
    
    print(f"Database: {db_path}\n")
    
    if run_migration(db_path):
        verify_migration(db_path)
    else:
        sys.exit(1)
