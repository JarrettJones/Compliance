#!/usr/bin/env python3
"""
Migration: Add DIMM Information firmware type
Adds the DIMM Information firmware type to the database and associates it with all programs
"""

import sqlite3
from datetime import datetime

DATABASE = 'firmware_checker.db'

def main():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    
    print("=" * 80)
    print("DIMM Information Firmware Type Migration")
    print("=" * 80)
    print()
    
    # Check if DIMM Information already exists
    existing = conn.execute(
        'SELECT * FROM firmware_types WHERE name = "DIMM Information"'
    ).fetchone()
    
    if existing:
        print(f"✓ DIMM Information firmware type already exists (ID: {existing['id']})")
    else:
        print("Adding DIMM Information firmware type...")
        conn.execute('''
            INSERT INTO firmware_types (category, name, description)
            VALUES ('Other Platform', 'DIMM Information', 'Memory module information via WMI')
        ''')
        conn.commit()
        
        dimm_type = conn.execute('SELECT * FROM firmware_types WHERE name = "DIMM Information"').fetchone()
        print(f"✓ DIMM Information added successfully (ID: {dimm_type['id']})")
    
    # Get the DIMM Information firmware type ID
    dimm_type = conn.execute('SELECT * FROM firmware_types WHERE name = "DIMM Information"').fetchone()
    dimm_type_id = dimm_type['id']
    
    # Associate with all programs
    print()
    print("Checking program associations...")
    programs = conn.execute('SELECT * FROM programs WHERE is_active = 1').fetchall()
    
    associations_added = 0
    for program in programs:
        # Check if already associated
        existing_assoc = conn.execute('''
            SELECT * FROM program_firmware_types 
            WHERE program_id = ? AND firmware_type_id = ?
        ''', (program['id'], dimm_type_id)).fetchone()
        
        if not existing_assoc:
            conn.execute('''
                INSERT INTO program_firmware_types (program_id, firmware_type_id)
                VALUES (?, ?)
            ''', (program['id'], dimm_type_id))
            print(f"  ✓ Associated with program: {program['name']}")
            associations_added += 1
        else:
            print(f"  - Already associated with program: {program['name']}")
    
    if associations_added > 0:
        conn.commit()
        print()
        print(f"✓ Added {associations_added} program associations")
    
    # Summary
    print()
    print("=" * 80)
    print("Migration Summary:")
    print("=" * 80)
    print(f"Firmware Type: DIMM Information (ID: {dimm_type_id})")
    print(f"Category: Other Platform")
    print(f"Programs Associated: {len(programs)}")
    print()
    print("✓ Migration completed successfully!")
    print("=" * 80)
    
    conn.close()

if __name__ == '__main__':
    main()
