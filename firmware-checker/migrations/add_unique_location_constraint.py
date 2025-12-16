"""
Add unique constraint to location names to prevent duplicates
"""
import sqlite3
import os

def run_migration():
    # Get the database path
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'firmware_checker.db')
    
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        print("Checking for duplicate locations...")
        
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
                print(f"   '{dup['norm_name']}' appears {dup['cnt']} times (IDs: {dup['ids']})")
            print("\n⚠️  Cannot add UNIQUE constraint with duplicates present.")
            print("   Please manually merge duplicate locations first.")
            return False
        
        print("✓ No duplicate locations found")
        
        # Check if unique constraint already exists
        indexes = cursor.execute('''
            SELECT name, sql FROM sqlite_master 
            WHERE type='index' AND tbl_name='locations'
        ''').fetchall()
        
        has_unique = False
        for idx in indexes:
            if idx['sql'] and 'UNIQUE' in idx['sql'].upper():
                has_unique = True
                print(f"✓ Unique constraint already exists: {idx['name']}")
                break
        
        if not has_unique:
            # Create unique index on location name
            print("Adding unique constraint to locations.name...")
            try:
                cursor.execute('CREATE UNIQUE INDEX idx_locations_name_unique ON locations(name)')
                print("✓ Successfully added unique constraint")
            except sqlite3.Error as e:
                print(f"❌ Error adding unique constraint: {e}")
                return False
        
        conn.commit()
        print("\n✓ Migration complete!")
        return True

if __name__ == '__main__':
    run_migration()
