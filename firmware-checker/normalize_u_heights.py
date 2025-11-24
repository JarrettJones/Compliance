"""
Script to normalize U-height values to positive integers only
Removes "U" prefix and leading zeros
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

def normalize_u_height(u_height):
    """
    Normalize U-height to positive integer
    Examples:
        "U10" -> "10"
        "U09" -> "9"
        "03" -> "3"
        "40" -> "40"
        "U1" -> "1"
    """
    if not u_height:
        return None
    
    # Remove any non-digit characters (including "U" prefix)
    digits = re.sub(r'[^\d]', '', str(u_height))
    
    if not digits:
        return None
    
    # Convert to int to remove leading zeros, then back to string
    try:
        return str(int(digits))
    except ValueError:
        return None

def normalize_all_u_heights():
    """Normalize all U-height values in the database"""
    with get_db_connection() as conn:
        # Get all systems with u_height
        systems = conn.execute('''
            SELECT id, u_height 
            FROM systems 
            WHERE u_height IS NOT NULL AND u_height != ''
        ''').fetchall()
        
        print(f"\nFound {len(systems)} systems with U-height data")
        print("\nNormalizing U-height values...\n")
        
        updated = 0
        unchanged = 0
        
        for system in systems:
            original = system['u_height']
            normalized = normalize_u_height(original)
            
            if normalized and normalized != original:
                conn.execute('''
                    UPDATE systems 
                    SET u_height = ? 
                    WHERE id = ?
                ''', (normalized, system['id']))
                print(f"  System {system['id']}: '{original}' -> '{normalized}'")
                updated += 1
            else:
                unchanged += 1
        
        print(f"\n✓ Updated: {updated} systems")
        print(f"✓ Already normalized: {unchanged} systems")
        
        # Show summary of current U-heights
        print("\n" + "="*60)
        print("Current U-height distribution:")
        print("="*60)
        u_heights = conn.execute('''
            SELECT u_height, COUNT(*) as count 
            FROM systems 
            WHERE u_height IS NOT NULL AND u_height != ''
            GROUP BY u_height 
            ORDER BY CAST(u_height AS INTEGER)
        ''').fetchall()
        
        for row in u_heights:
            print(f"  U{row['u_height']}: {row['count']} systems")

def main():
    print("\n" + "="*60)
    print("U-HEIGHT NORMALIZATION")
    print("="*60)
    
    normalize_all_u_heights()
    
    print("\n" + "="*60)
    print("NORMALIZATION COMPLETE")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
