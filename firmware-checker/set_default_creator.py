#!/usr/bin/env python3
"""
Set default creator for systems without a creator
This script sets jarrettjones as the creator for any systems that don't have a creator assigned
"""

import sqlite3
import sys

def set_default_creator():
    """Set jarrettjones as creator for systems without a creator"""
    
    # Connect to database
    conn = sqlite3.connect('firmware_checker.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        # Find jarrettjones user
        user = cursor.execute('''
            SELECT id, username FROM users WHERE username = ?
        ''', ('jarrettjones',)).fetchone()
        
        if not user:
            print("ERROR: User 'jarrettjones' not found in database!")
            print("Available users:")
            users = cursor.execute('SELECT id, username FROM users ORDER BY username').fetchall()
            for u in users:
                print(f"  - {u['username']} (ID: {u['id']})")
            return 1
        
        user_id = user['id']
        print(f"Found user: {user['username']} (ID: {user_id})")
        print()
        
        # Find systems without a creator
        systems_without_creator = cursor.execute('''
            SELECT id, name, rscm_ip 
            FROM systems 
            WHERE created_by IS NULL
            ORDER BY name
        ''').fetchall()
        
        if not systems_without_creator:
            print("✓ All systems already have a creator assigned!")
            return 0
        
        print(f"Found {len(systems_without_creator)} systems without a creator:")
        print()
        for system in systems_without_creator:
            print(f"  - {system['name']} ({system['rscm_ip']})")
        print()
        
        # Ask for confirmation
        response = input(f"Set jarrettjones as creator for these {len(systems_without_creator)} systems? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("Cancelled.")
            return 0
        
        # Update systems
        cursor.execute('''
            UPDATE systems 
            SET created_by = ? 
            WHERE created_by IS NULL
        ''', (user_id,))
        
        updated_count = cursor.rowcount
        conn.commit()
        
        print()
        print(f"✓ Successfully updated {updated_count} systems!")
        print(f"  All systems now have jarrettjones as the creator")
        
        # Verify
        remaining = cursor.execute('''
            SELECT COUNT(*) as count FROM systems WHERE created_by IS NULL
        ''').fetchone()['count']
        
        if remaining > 0:
            print(f"WARNING: {remaining} systems still have no creator")
            return 1
        
        return 0
        
    except Exception as e:
        print(f"ERROR: {str(e)}")
        conn.rollback()
        return 1
    finally:
        conn.close()

if __name__ == '__main__':
    sys.exit(set_default_creator())
