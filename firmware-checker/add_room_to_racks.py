"""
Migration script to add room field to racks table
"""
import sqlite3
from contextlib import contextmanager

DB_PATH = 'firmware_checker.db'

@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def add_room_column():
    """Add room column to racks table"""
    with get_db_connection() as conn:
        try:
            # Check if column already exists
            cursor = conn.execute('PRAGMA table_info(racks)')
            columns = [col['name'] for col in cursor.fetchall()]
            
            if 'room' in columns:
                print("✓ Room column already exists in racks table")
                return
            
            # Add room column
            conn.execute('ALTER TABLE racks ADD COLUMN room TEXT')
            print("✓ Added room column to racks table")
            
            # Set default room values for existing racks
            conn.execute('''
                UPDATE racks 
                SET room = 'Room 2045'
                WHERE room IS NULL
            ''')
            print("✓ Set default room values for existing racks")
            
        except sqlite3.OperationalError as e:
            print(f"✗ Error: {e}")
            raise

def view_racks():
    """Display current racks with new room field"""
    with get_db_connection() as conn:
        racks = conn.execute('''
            SELECT id, name, location, room, rack_type
            FROM racks
            ORDER BY location, room, name
        ''').fetchall()
        
        print("\nRacks with room information:")
        print("="*80)
        for rack in racks:
            print(f"  {rack['name']} - {rack['location']}, {rack['room'] or '(no room)'} ({rack['rack_type']})")
        print("="*80)
        print(f"Total: {len(racks)} racks")

def main():
    print("="*60)
    print("ADD ROOM FIELD TO RACKS TABLE")
    print("="*60)
    print("\nThis will:")
    print("1. Add a 'room' column to the racks table")
    print("2. Set default room value for existing racks")
    print()
    
    response = input("Proceed with migration? (yes/no): ")
    if response.lower() != 'yes':
        print("Migration cancelled.")
        return 1
    
    print("\nStarting migration...\n")
    
    try:
        add_room_column()
        view_racks()
        
        print("\n✓ Migration completed successfully!")
        print("\nNext steps:")
        print("1. Update rack forms to include room field")
        print("2. Update racks.html to group by room")
        print("3. Review and update room values for each rack as needed")
        
        return 0
        
    except Exception as e:
        print(f"\n✗ Migration failed: {e}")
        return 1

if __name__ == '__main__':
    exit(main())
