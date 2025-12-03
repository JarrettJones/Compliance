"""
Migration script to create rscm_firmware_checks table
Run this script to add RSCM firmware checking capability
"""

import sqlite3
import sys

def migrate_database(db_path='firmware_checker.db'):
    """Add rscm_firmware_checks table to database"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if table already exists
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='rscm_firmware_checks'
        """)
        
        if cursor.fetchone():
            print("✓ rscm_firmware_checks table already exists")
            return True
        
        # Create rscm_firmware_checks table
        print("Creating rscm_firmware_checks table...")
        cursor.execute('''
            CREATE TABLE rscm_firmware_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rack_id INTEGER NOT NULL,
                rscm_ip TEXT NOT NULL,
                rscm_port INTEGER DEFAULT 8080,
                position TEXT,
                firmware_data TEXT,
                status TEXT DEFAULT 'completed',
                error_message TEXT,
                check_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY (rack_id) REFERENCES racks(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # Create index for faster lookups
        cursor.execute('''
            CREATE INDEX idx_rscm_checks_rack 
            ON rscm_firmware_checks(rack_id, check_date DESC)
        ''')
        
        cursor.execute('''
            CREATE INDEX idx_rscm_checks_date 
            ON rscm_firmware_checks(check_date DESC)
        ''')
        
        conn.commit()
        print("✓ rscm_firmware_checks table created successfully")
        print("✓ Indexes created successfully")
        
        # Show table structure
        cursor.execute("PRAGMA table_info(rscm_firmware_checks)")
        columns = cursor.fetchall()
        print("\nTable structure:")
        for col in columns:
            print(f"  - {col[1]} ({col[2]})")
        
        conn.close()
        return True
        
    except sqlite3.Error as e:
        print(f"✗ Database error: {e}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return False

if __name__ == '__main__':
    db_path = sys.argv[1] if len(sys.argv) > 1 else 'firmware_checker.db'
    
    print("="*80)
    print("RSCM Firmware Checks Table Migration")
    print("="*80)
    print(f"Database: {db_path}\n")
    
    success = migrate_database(db_path)
    
    if success:
        print("\n" + "="*80)
        print("Migration completed successfully!")
        print("="*80)
        sys.exit(0)
    else:
        print("\n" + "="*80)
        print("Migration failed!")
        print("="*80)
        sys.exit(1)
