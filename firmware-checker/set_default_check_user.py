#!/usr/bin/env python3
"""
Set default user for firmware checks without a user_id
This script sets jarrettjones as the user for any firmware checks that don't have a user_id assigned
"""

import sqlite3
import sys

def set_default_check_user():
    """Set jarrettjones as user for firmware checks without a user_id"""
    
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
        
        # Find firmware checks without a user_id
        checks_without_user = cursor.execute('''
            SELECT fc.id, fc.check_date, fc.status, s.name as system_name
            FROM firmware_checks fc
            JOIN systems s ON fc.system_id = s.id
            WHERE fc.user_id IS NULL
            ORDER BY fc.check_date DESC
        ''').fetchall()
        
        if not checks_without_user:
            print("✓ All firmware checks already have a user assigned!")
            return 0
        
        print(f"Found {len(checks_without_user)} firmware checks without a user:")
        print()
        
        # Show first 10
        display_count = min(10, len(checks_without_user))
        for i, check in enumerate(checks_without_user[:display_count]):
            print(f"  - Check #{check['id']}: {check['system_name']} - {check['check_date'][:19]} ({check['status']})")
        
        if len(checks_without_user) > display_count:
            print(f"  ... and {len(checks_without_user) - display_count} more")
        
        print()
        
        # Ask for confirmation
        response = input(f"Set jarrettjones as user for these {len(checks_without_user)} checks? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("Cancelled.")
            return 0
        
        # Update firmware checks
        cursor.execute('''
            UPDATE firmware_checks 
            SET user_id = ? 
            WHERE user_id IS NULL
        ''', (user_id,))
        
        updated_count = cursor.rowcount
        conn.commit()
        
        print()
        print(f"✓ Successfully updated {updated_count} firmware checks!")
        print(f"  All checks now have jarrettjones as the user")
        
        # Verify
        remaining = cursor.execute('''
            SELECT COUNT(*) as count FROM firmware_checks WHERE user_id IS NULL
        ''').fetchone()['count']
        
        if remaining > 0:
            print(f"WARNING: {remaining} firmware checks still have no user")
            return 1
        
        print()
        print("Now you should see 'My Recent Checks' on the dashboard!")
        
        return 0
        
    except Exception as e:
        print(f"ERROR: {str(e)}")
        conn.rollback()
        return 1
    finally:
        conn.close()

if __name__ == '__main__':
    sys.exit(set_default_check_user())
