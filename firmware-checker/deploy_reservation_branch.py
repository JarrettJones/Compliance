"""
Deployment script for reservation branch to production server
Runs all necessary migrations and updates for the reservation system
"""
import sqlite3
import os
import sys
from datetime import datetime

def backup_database(db_path):
    """Create a backup of the database before making changes"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f"{db_path}_backup_{timestamp}.db"
    
    print(f"\n=== Creating database backup ===")
    print(f"Backup path: {backup_path}")
    
    try:
        import shutil
        shutil.copy2(db_path, backup_path)
        print(f"✓ Database backed up successfully")
        return backup_path
    except Exception as e:
        print(f"❌ Failed to create backup: {e}")
        return None

def add_timezone_column(conn):
    """Add timezone column to users table with Pacific Time default"""
    print("\n=== Adding timezone column to users table ===")
    cursor = conn.cursor()
    
    try:
        # Check if timezone column already exists
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'timezone' in columns:
            print("✓ Timezone column already exists")
            
            # Update any users still on UTC to Pacific Time
            result = cursor.execute("""
                UPDATE users 
                SET timezone = 'America/Los_Angeles' 
                WHERE timezone IS NULL OR timezone = 'UTC'
            """)
            updated = result.rowcount
            if updated > 0:
                print(f"✓ Updated {updated} user(s) from UTC to PST/PDT")
            else:
                print("✓ All users already have Pacific timezone")
        else:
            # Add timezone column with Pacific Time as default
            cursor.execute("""
                ALTER TABLE users 
                ADD COLUMN timezone TEXT DEFAULT 'America/Los_Angeles'
            """)
            print("✓ Successfully added timezone column with Pacific Time default")
            
            # Update existing NULL values to Pacific Time
            cursor.execute("""
                UPDATE users 
                SET timezone = 'America/Los_Angeles' 
                WHERE timezone IS NULL
            """)
            print("✓ Set all existing users to Pacific timezone")
        
        conn.commit()
        return True
        
    except sqlite3.Error as e:
        print(f"❌ Error adding timezone column: {e}")
        return False

def add_unique_location_constraint(conn):
    """Add unique constraint to location names"""
    print("\n=== Adding unique constraint to locations ===")
    cursor = conn.cursor()
    
    try:
        # Check for existing duplicates
        duplicates = cursor.execute('''
            SELECT LOWER(TRIM(name)) as norm_name, COUNT(*) as cnt, GROUP_CONCAT(id) as ids
            FROM locations
            GROUP BY LOWER(TRIM(name))
            HAVING COUNT(*) > 1
        ''').fetchall()
        
        if duplicates:
            print(f"⚠️  Found {len(duplicates)} duplicate location name(s)!")
            for dup in duplicates:
                print(f"   '{dup[0]}' appears {dup[1]} times (IDs: {dup[2]})")
            print("   ⚠️  Please manually merge duplicates before continuing")
            return False
        
        print("✓ No duplicate locations found")
        
        # Check if unique constraint already exists
        indexes = cursor.execute('''
            SELECT name, sql FROM sqlite_master 
            WHERE type='index' AND tbl_name='locations'
        ''').fetchall()
        
        has_unique = False
        for idx in indexes:
            if idx[1] and 'UNIQUE' in idx[1].upper():
                has_unique = True
                print(f"✓ Unique constraint already exists: {idx[0]}")
                break
        
        if not has_unique:
            cursor.execute('CREATE UNIQUE INDEX idx_locations_name_unique ON locations(name)')
            print("✓ Successfully added unique constraint to locations")
        
        conn.commit()
        return True
        
    except sqlite3.Error as e:
        print(f"❌ Error adding unique constraint: {e}")
        return False

def add_reservations_table(conn):
    """Create reservations table if it doesn't exist"""
    print("\n=== Checking reservations table ===")
    cursor = conn.cursor()
    
    try:
        # Check if reservations table exists
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='reservations'
        """)
        
        if cursor.fetchone():
            print("✓ Reservations table already exists")
        else:
            print("Creating reservations table...")
            cursor.execute("""
                CREATE TABLE reservations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    system_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    start_time TIMESTAMP NOT NULL,
                    end_time TIMESTAMP NOT NULL,
                    purpose TEXT,
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    FOREIGN KEY (system_id) REFERENCES systems (id),
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    CONSTRAINT valid_status CHECK (status IN ('active', 'completed', 'cancelled'))
                )
            """)
            
            # Create indexes for performance
            cursor.execute("""
                CREATE INDEX idx_reservations_system_id ON reservations(system_id)
            """)
            cursor.execute("""
                CREATE INDEX idx_reservations_user_id ON reservations(user_id)
            """)
            cursor.execute("""
                CREATE INDEX idx_reservations_status ON reservations(status)
            """)
            cursor.execute("""
                CREATE INDEX idx_reservations_times ON reservations(start_time, end_time)
            """)
            
            print("✓ Successfully created reservations table with indexes")
        
        conn.commit()
        return True
        
    except sqlite3.Error as e:
        print(f"❌ Error creating reservations table: {e}")
        return False

def verify_migrations(conn):
    """Verify all migrations were successful"""
    print("\n=== Verifying migrations ===")
    cursor = conn.cursor()
    
    all_good = True
    
    # Check timezone column
    cursor.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'timezone' in columns:
        print("✓ Users.timezone column exists")
        
        # Check user timezones
        cursor.execute("SELECT COUNT(*) FROM users WHERE timezone = 'America/Los_Angeles'")
        pst_users = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]
        print(f"  {pst_users}/{total_users} users on Pacific timezone")
    else:
        print("❌ Users.timezone column missing")
        all_good = False
    
    # Check unique constraint on locations
    cursor.execute("""
        SELECT name FROM sqlite_master 
        WHERE type='index' AND tbl_name='locations' AND sql LIKE '%UNIQUE%'
    """)
    if cursor.fetchone():
        print("✓ Locations unique constraint exists")
    else:
        print("❌ Locations unique constraint missing")
        all_good = False
    
    # Check reservations table
    cursor.execute("""
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='reservations'
    """)
    if cursor.fetchone():
        print("✓ Reservations table exists")
        cursor.execute("SELECT COUNT(*) FROM reservations")
        count = cursor.fetchone()[0]
        print(f"  {count} reservation(s) in database")
    else:
        print("❌ Reservations table missing")
        all_good = False
    
    return all_good

def main():
    # Determine database path
    if len(sys.argv) > 1:
        db_path = sys.argv[1]
    else:
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'firmware_checker.db')
    
    print("=" * 60)
    print("RESERVATION BRANCH DEPLOYMENT SCRIPT")
    print("=" * 60)
    print(f"Database: {db_path}")
    
    if not os.path.exists(db_path):
        print(f"\n❌ Database not found: {db_path}")
        sys.exit(1)
    
    # Create backup
    backup_path = backup_database(db_path)
    if not backup_path:
        print("\n❌ Cannot proceed without backup. Exiting.")
        sys.exit(1)
    
    # Connect to database
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        
        # Run migrations
        success = True
        success = add_timezone_column(conn) and success
        success = add_unique_location_constraint(conn) and success
        success = add_reservations_table(conn) and success
        
        # Verify all changes
        if success:
            success = verify_migrations(conn)
        
        conn.close()
        
        # Summary
        print("\n" + "=" * 60)
        if success:
            print("✓ DEPLOYMENT SUCCESSFUL")
            print("=" * 60)
            print("\nAll migrations completed successfully!")
            print(f"Backup saved at: {backup_path}")
            print("\nNext steps:")
            print("1. Restart the Flask application")
            print("2. Test the reservation system")
            print("3. Verify timezone displays correctly")
            return 0
        else:
            print("❌ DEPLOYMENT FAILED")
            print("=" * 60)
            print("\nSome migrations failed. Check errors above.")
            print(f"Database backup available at: {backup_path}")
            print("You can restore from backup if needed:")
            print(f"  cp {backup_path} {db_path}")
            return 1
            
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        print(f"Database backup available at: {backup_path}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
