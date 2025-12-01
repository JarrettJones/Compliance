#!/usr/bin/env python3
"""
Script to standardize locations and buildings in system descriptions and racks
Set all to: Redmond - Building 50
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

def standardize_system_descriptions():
    """Standardize location and building in system descriptions"""
    with get_db_connection() as conn:
        systems = conn.execute('''
            SELECT id, description
            FROM systems
            WHERE description IS NOT NULL AND description != ''
        ''').fetchall()
        
        print(f"\nProcessing {len(systems)} systems...\n")
        
        updated = 0
        unchanged = 0
        
        for system in systems:
            description = system['description']
            original_desc = description
            
            # Parse and rebuild description with standardized values
            parts = description.split('|')
            new_parts = []
            has_geo = False
            has_building = False
            
            for part in parts:
                part = part.strip()
                if part.startswith('Host:'):
                    new_parts.append(part)
                elif part.startswith('Geo:'):
                    new_parts.append('Geo: Redmond')
                    has_geo = True
                elif part.startswith('Building:'):
                    new_parts.append('Building: Building 50')
                    has_building = True
                elif part.startswith('Room:'):
                    new_parts.append(part)
                elif part.startswith('Rack:'):
                    new_parts.append(part)
                elif part.startswith('U:'):
                    new_parts.append(part)
                else:
                    new_parts.append(part)
            
            # Add Geo and Building if missing
            if not has_geo:
                # Insert after Host if it exists
                insert_pos = 1 if any(p.startswith('Host:') for p in new_parts) else 0
                new_parts.insert(insert_pos, 'Geo: Redmond')
            
            if not has_building:
                # Insert after Geo
                geo_index = next((i for i, p in enumerate(new_parts) if p.startswith('Geo:')), -1)
                insert_pos = geo_index + 1 if geo_index >= 0 else 1
                new_parts.insert(insert_pos, 'Building: Building 50')
            
            new_description = ' | '.join(new_parts)
            
            if new_description != original_desc:
                conn.execute('''
                    UPDATE systems 
                    SET description = ?
                    WHERE id = ?
                ''', (new_description, system['id']))
                print(f"System {system['id']}:")
                print(f"  Old: {original_desc}")
                print(f"  New: {new_description}")
                print()
                updated += 1
            else:
                unchanged += 1
        
        print(f"\nSystems: ✓ Updated: {updated}, ✓ Unchanged: {unchanged}")

def standardize_rack_locations():
    """Standardize rack locations"""
    with get_db_connection() as conn:
        racks = conn.execute('''
            SELECT id, name, location
            FROM racks
        ''').fetchall()
        
        print(f"\nProcessing {len(racks)} racks...\n")
        
        updated = 0
        unchanged = 0
        standard_location = "Redmond - Building 50"
        
        for rack in racks:
            if rack['location'] != standard_location:
                conn.execute('''
                    UPDATE racks 
                    SET location = ?
                    WHERE id = ?
                ''', (standard_location, rack['id']))
                print(f"Rack {rack['id']} ({rack['name']}):")
                print(f"  Old: {rack['location']}")
                print(f"  New: {standard_location}")
                print()
                updated += 1
            else:
                unchanged += 1
        
        print(f"Racks: ✓ Updated: {updated}, ✓ Unchanged: {unchanged}")

if __name__ == '__main__':
    print("="*70)
    print("LOCATION STANDARDIZATION")
    print("="*70)
    print("\nSetting all locations to: Redmond - Building 50\n")
    
    standardize_system_descriptions()
    print("\n" + "="*70 + "\n")
    standardize_rack_locations()
    
    print("\n" + "="*70)
    print("STANDARDIZATION COMPLETE")
    print("="*70)
