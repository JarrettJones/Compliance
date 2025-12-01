"""
Fix room assignments for B08-Rack and C04-Rack to Room 1157
These racks had conflicting room numbers in their systems but should all be in Room 1157
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

def show_current_state():
    """Show current rack room assignments"""
    with get_db_connection() as conn:
        racks = conn.execute('''
            SELECT name, room, location
            FROM racks
            WHERE name IN ('B08-Rack', 'C04-Rack')
            ORDER BY name
        ''').fetchall()
        
        print("\nCurrent state:")
        print("="*60)
        for rack in racks:
            print(f"  {rack['name']}: {rack['room']} at {rack['location']}")
        print("="*60)

def update_rooms():
    """Update B08-Rack and C04-Rack to Room 1157"""
    with get_db_connection() as conn:
        print("\nUpdating rooms...")
        
        # Update B08-Rack
        conn.execute('''
            UPDATE racks
            SET room = 'Room 1157'
            WHERE name = 'B08-Rack'
        ''')
        print("  ✓ B08-Rack → Room 1157")
        
        # Update C04-Rack
        conn.execute('''
            UPDATE racks
            SET room = 'Room 1157'
            WHERE name = 'C04-Rack'
        ''')
        print("  ✓ C04-Rack → Room 1157")

def show_final_state():
    """Show final rack room assignments grouped by room"""
    with get_db_connection() as conn:
        racks = conn.execute('''
            SELECT name, room, location
            FROM racks
            ORDER BY room, name
        ''').fetchall()
        
        print("\n" + "="*60)
        print("FINAL RACK ROOM ASSIGNMENTS")
        print("="*60)
        
        current_room = None
        for rack in racks:
            room = rack['room'] or '(no room)'
            if room != current_room:
                print(f"\n{room}:")
                current_room = room
            print(f"  - {rack['name']}")
        
        print("="*60)
        
        # Count by room
        summary = conn.execute('''
            SELECT room, COUNT(*) as count
            FROM racks
            GROUP BY room
            ORDER BY room
        ''').fetchall()
        
        print("\nSummary:")
        for row in summary:
            print(f"  {row['room']}: {row['count']} racks")

def main():
    print("="*60)
    print("FIX ROOM ASSIGNMENTS FOR B08-RACK AND C04-RACK")
    print("="*60)
    print("\nThis script will:")
    print("  - Set B08-Rack room to 'Room 1157'")
    print("  - Set C04-Rack room to 'Room 1157'")
    print()
    
    show_current_state()
    
    response = input("\nProceed with updates? (yes/no): ")
    if response.lower() != 'yes':
        print("Update cancelled.")
        return 1
    
    try:
        update_rooms()
        show_final_state()
        
        print("\n✓ Room assignments updated successfully!")
        return 0
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        return 1

if __name__ == '__main__':
    exit(main())
