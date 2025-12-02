#!/usr/bin/env python3
"""
Script to delete the empty E08 rack (ID: 13)
"""
import sqlite3
import sys

def delete_empty_e08(db_path='firmware_checker.db'):
    """Delete the empty E08 rack"""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Check the rack first
        rack = cursor.execute("""
            SELECT id, name, location, room,
                   (SELECT COUNT(*) FROM systems WHERE rack_id = racks.id) as system_count
            FROM racks 
            WHERE id = 13
        """).fetchone()
        
        if not rack:
            print("Rack ID 13 not found.")
            conn.close()
            return
        
        print("=" * 80)
        print("RACK TO BE DELETED:")
        print("=" * 80)
        print(f"ID: {rack['id']}")
        print(f"Name: {rack['name']}")
        print(f"Location: {rack['location']}")
        print(f"Room: {rack['room']}")
        print(f"System Count: {rack['system_count']}")
        print()
        
        if rack['system_count'] > 0:
            print("ERROR: This rack has systems! Will not delete.")
            conn.close()
            sys.exit(1)
        
        # Confirm deletion
        response = input("Are you sure you want to delete this rack? Type 'DELETE' to confirm: ")
        
        if response != 'DELETE':
            print("Deletion cancelled.")
            conn.close()
            return
        
        # Delete the rack
        cursor.execute("DELETE FROM racks WHERE id = 13")
        conn.commit()
        
        print()
        print("=" * 80)
        print("✓ Rack deleted successfully!")
        print("=" * 80)
        
        conn.close()
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    db_path = sys.argv[1] if len(sys.argv) > 1 else 'firmware_checker.db'
    delete_empty_e08(db_path)
