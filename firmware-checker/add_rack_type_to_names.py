#!/usr/bin/env python3
"""
Script to add rack type suffix to rack names to differentiate racks and benches.
For example: "B04" becomes "B04-Rack" or "B04-Bench"
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

def view_current_racks():
    """Display all current rack names and types"""
    with get_db_connection() as conn:
        racks = conn.execute('''
            SELECT id, name, rack_type, location
            FROM racks
            ORDER BY name, rack_type
        ''').fetchall()
        
        print("\n" + "=" * 70)
        print("CURRENT RACK NAMES")
        print("=" * 70)
        for rack in racks:
            print(f"  ID {rack['id']}: {rack['name']} ({rack['rack_type']}) - {rack['location']}")
        print("=" * 70)

def add_type_suffix_to_names():
    """Add rack type suffix to rack names"""
    with get_db_connection() as conn:
        racks = conn.execute('''
            SELECT id, name, rack_type
            FROM racks
            ORDER BY id
        ''').fetchall()
        
        print("\nAdding type suffix to rack names...\n")
        
        updated = 0
        unchanged = 0
        
        for rack in racks:
            original = rack['name']
            suffix = "-Rack" if rack['rack_type'] == 'rack' else "-Bench"
            
            # Check if already has the suffix
            if original.endswith(suffix):
                unchanged += 1
                continue
            
            # Check if it has ANY type suffix already
            if original.endswith('-Rack') or original.endswith('-Bench'):
                unchanged += 1
                continue
            
            new_name = f"{original}{suffix}"
            
            # Check if new name already exists
            existing = conn.execute('''
                SELECT id FROM racks 
                WHERE name = ? AND id != ?
            ''', (new_name, rack['id'])).fetchone()
            
            if existing:
                print(f"  Rack {rack['id']}: '{original}' -> SKIPPED ('{new_name}' already exists)")
                unchanged += 1
            else:
                conn.execute('''
                    UPDATE racks 
                    SET name = ? 
                    WHERE id = ?
                ''', (new_name, rack['id']))
                print(f"  Rack {rack['id']}: '{original}' -> '{new_name}'")
                updated += 1
        
        print(f"\n✓ Updated: {updated} racks")
        print(f"✓ Already correct: {unchanged} racks")

def main():
    print("=" * 70)
    print("ADD RACK TYPE SUFFIX TO NAMES")
    print("=" * 70)
    
    view_current_racks()
    
    print("\nThis will add '-Rack' or '-Bench' suffix to each rack name.")
    print("Example: 'B04' (rack) -> 'B04-Rack'")
    print("         'B04' (bench) -> 'B04-Bench'\n")
    
    add_type_suffix_to_names()
    
    view_current_racks()
    
    print("\n" + "=" * 70)
    print("COMPLETE")
    print("=" * 70)

if __name__ == '__main__':
    main()
