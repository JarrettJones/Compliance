"""
Migration script to add u_height column to systems table and populate it from description field
"""
import sqlite3
import re
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

def extract_u_height(description):
    """Extract U height from description string"""
    if not description:
        return None
    
    # Look for patterns like "U: U10", "U: U10-U12", "U10", etc.
    patterns = [
        r'U:\s*([U\d\-]+)',  # U: U10 or U: U10-U12
        r'\b(U\d+(?:-U\d+)?)\b',  # U10 or U10-U12
    ]
    
    for pattern in patterns:
        match = re.search(pattern, description, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return None

def add_u_height_column():
    """Add u_height column to systems table"""
    with get_db_connection() as conn:
        # Check if column already exists
        cursor = conn.execute("PRAGMA table_info(systems)")
        columns = [row['name'] for row in cursor.fetchall()]
        
        if 'u_height' in columns:
            print("✓ u_height column already exists")
            return False
        
        # Add the column
        print("Adding u_height column to systems table...")
        conn.execute('''
            ALTER TABLE systems 
            ADD COLUMN u_height TEXT
        ''')
        print("✓ u_height column added")
        return True

def migrate_u_height_data():
    """Migrate U height data from description to u_height column"""
    with get_db_connection() as conn:
        # Get all systems
        systems = conn.execute('SELECT id, description FROM systems').fetchall()
        
        updated = 0
        for system in systems:
            u_height = extract_u_height(system['description'])
            if u_height:
                conn.execute('''
                    UPDATE systems 
                    SET u_height = ? 
                    WHERE id = ?
                ''', (u_height, system['id']))
                updated += 1
                print(f"  System {system['id']}: {u_height}")
        
        print(f"\n✓ Migrated {updated} systems with U-height data")

def main():
    print("\n" + "="*60)
    print("U-HEIGHT COLUMN MIGRATION")
    print("="*60)
    
    # Add column
    added = add_u_height_column()
    
    if added:
        # Migrate data
        print("\nMigrating U-height data from description field...")
        migrate_u_height_data()
    
    print("\n" + "="*60)
    print("MIGRATION COMPLETE")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
