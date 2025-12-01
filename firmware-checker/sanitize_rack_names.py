"""
Script to view and sanitize rack/bench names
Removes redundant "Rack" prefix from rack names
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
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def view_current_racks():
    """Display current rack names"""
    with get_db_connection() as conn:
        racks = conn.execute('''
            SELECT id, name, location, rack_type
            FROM racks
            ORDER BY name
        ''').fetchall()
        
        print("\nCurrent rack names:")
        print("="*60)
        for rack in racks:
            print(f"  ID {rack['id']}: {rack['name']} ({rack['rack_type']}) - {rack['location']}")
        
        return racks

def sanitize_rack_name(name, rack_type):
    """
    Remove redundant 'Rack' or 'Bench' from names
    Examples:
        "Rack B04" -> "B04"
        "Rack B06" -> "B06"
        "B07" -> "B07" (unchanged)
    """
    name = name.strip()
    
    # Remove "Rack " prefix (case insensitive)
    if name.lower().startswith('rack '):
        name = name[5:].strip()
    
    # Remove "Bench " prefix (case insensitive)
    if name.lower().startswith('bench '):
        name = name[6:].strip()
    
    return name

def sanitize_all_racks():
    """Sanitize all rack names in the database"""
    with get_db_connection() as conn:
        racks = conn.execute('''
            SELECT id, name, rack_type
            FROM racks
            ORDER BY id
        ''').fetchall()
        
        print("\nSanitizing rack names...\n")
        
        updated = 0
        unchanged = 0
        skipped = 0
        
        for rack in racks:
            original = rack['name']
            sanitized = sanitize_rack_name(original, rack['rack_type'])
            
            if sanitized != original:
                # Check if sanitized name already exists
                existing = conn.execute('''
                    SELECT id FROM racks 
                    WHERE name = ? AND id != ?
                ''', (sanitized, rack['id'])).fetchone()
                
                if existing:
                    print(f"  Rack {rack['id']}: '{original}' -> SKIPPED ('{sanitized}' already exists as Rack {existing['id']})")
                    skipped += 1
                else:
                    conn.execute('''
                        UPDATE racks 
                        SET name = ? 
                        WHERE id = ?
                    ''', (sanitized, rack['id']))
                    print(f"  Rack {rack['id']}: '{original}' -> '{sanitized}'")
                    updated += 1
            else:
                unchanged += 1
        
        print(f"\n✓ Updated: {updated} racks")
        print(f"✓ Already clean: {unchanged} racks")
        if skipped > 0:
            print(f"⚠ Skipped: {skipped} racks (would create duplicates)")
            print("\nNote: You may want to manually merge duplicate racks or delete the redundant 'Rack X' entries.")

def main():
    print("\n" + "="*60)
    print("RACK NAME SANITIZATION")
    print("="*60)
    
    # Show current state
    view_current_racks()
    
    # Sanitize
    sanitize_all_racks()
    
    # Show new state
    print("\n" + "="*60)
    view_current_racks()
    
    print("\n" + "="*60)
    print("SANITIZATION COMPLETE")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
