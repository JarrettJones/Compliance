#!/usr/bin/env python3
"""
Script to merge duplicate rack entries where one has "Rack " prefix and one doesn't.
Will reassign systems from the "Rack X" version to the clean "X" version, then delete the duplicate.
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
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def find_duplicate_racks():
    """Find racks where 'Rack X' and 'X' both exist"""
    with get_db_connection() as conn:
        racks = conn.execute('''
            SELECT id, name, location
            FROM racks
            ORDER BY name
        ''').fetchall()
        
        duplicates = []
        rack_dict = {r['name']: r for r in racks}
        
        for rack in racks:
            if rack['name'].lower().startswith('rack '):
                clean_name = rack['name'][5:]  # Remove "Rack "
                if clean_name in rack_dict:
                    duplicates.append({
                        'old_id': rack['id'],
                        'old_name': rack['name'],
                        'old_location': rack['location'],
                        'new_id': rack_dict[clean_name]['id'],
                        'new_name': rack_dict[clean_name]['name'],
                        'new_location': rack_dict[clean_name]['location']
                    })
        
        return duplicates

def get_system_count(rack_id):
    """Get count of systems assigned to a rack"""
    with get_db_connection() as conn:
        result = conn.execute('''
            SELECT COUNT(*) as count
            FROM systems
            WHERE rack_id = ?
        ''', (rack_id,)).fetchone()
        return result['count']

def merge_racks(old_rack_id, new_rack_id):
    """Reassign systems from old_rack_id to new_rack_id, then delete old rack"""
    with get_db_connection() as conn:
        # Reassign systems
        conn.execute('''
            UPDATE systems
            SET rack_id = ?
            WHERE rack_id = ?
        ''', (new_rack_id, old_rack_id))
        
        systems_moved = conn.total_changes
        
        # Delete old rack
        conn.execute('''
            DELETE FROM racks
            WHERE id = ?
        ''', (old_rack_id,))
        
        return systems_moved

def main():
    print("=" * 70)
    print("RACK DUPLICATE MERGER")
    print("=" * 70)
    
    # Find duplicates
    duplicates = find_duplicate_racks()
    
    if not duplicates:
        print("\n✓ No duplicate racks found!")
        return
    
    print(f"\nFound {len(duplicates)} duplicate rack(s):\n")
    
    for dup in duplicates:
        old_count = get_system_count(dup['old_id'])
        new_count = get_system_count(dup['new_id'])
        
        print(f"  Duplicate: '{dup['old_name']}' (ID {dup['old_id']})")
        print(f"    Location: {dup['old_location']}")
        print(f"    Systems: {old_count}")
        print(f"  →  Merging into: '{dup['new_name']}' (ID {dup['new_id']})")
        print(f"    Location: {dup['new_location']}")
        print(f"    Systems: {new_count}")
        print()
    
    # Perform merge
    print("Merging duplicates...\n")
    
    total_moved = 0
    for dup in duplicates:
        moved = merge_racks(dup['old_id'], dup['new_id'])
        total_moved += moved
        print(f"  ✓ Merged Rack {dup['old_id']} ('{dup['old_name']}') into Rack {dup['new_id']} ('{dup['new_name']}')")
        print(f"    Moved {moved} system(s)")
    
    print(f"\n✓ Merge complete!")
    print(f"  Total systems reassigned: {total_moved}")
    print(f"  Duplicate racks removed: {len(duplicates)}")

if __name__ == '__main__':
    main()
