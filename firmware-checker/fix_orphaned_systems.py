"""
Find and fix systems with rack metadata but no rack_id
Creates missing racks and links systems to them
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

def parse_metadata_from_description(description):
    """Parse metadata from system description"""
    metadata = {
        'hostname': '',
        'geo': '',
        'building': '',
        'room': '',
        'rack': '',
        'u_height': ''
    }
    
    if not description:
        return metadata
    
    parts = description.split('|')
    for part in parts:
        part = part.strip()
        if part.startswith('Host:'):
            metadata['hostname'] = part.replace('Host:', '').strip()
        elif part.startswith('Geo:'):
            metadata['geo'] = part.replace('Geo:', '').strip()
        elif part.startswith('Building:'):
            metadata['building'] = part.replace('Building:', '').strip()
        elif part.startswith('Room:'):
            metadata['room'] = part.replace('Room:', '').strip()
        elif part.startswith('Rack:'):
            metadata['rack'] = part.replace('Rack:', '').strip()
        elif part.startswith('U:'):
            metadata['u_height'] = part.replace('U:', '').strip()
    
    return metadata

def extract_room_from_hostname(hostname):
    """Extract room number from hostname pattern like C41431157B0234B"""
    if not hostname:
        return None
    
    # Pattern: C4143 followed by 4 digits (room number)
    match = re.search(r'C4143(\d{4})', hostname)
    if match:
        room_num = match.group(1)
        return f"Room {room_num}"
    
    return None

def find_orphaned_systems():
    """Find systems with rack metadata but no rack_id"""
    with get_db_connection() as conn:
        systems = conn.execute('''
            SELECT id, name, description, rack_id
            FROM systems
            WHERE rack_id IS NULL OR rack_id = 0
            ORDER BY name
        ''').fetchall()
        
        orphaned = []
        
        for system in systems:
            metadata = parse_metadata_from_description(system['description'])
            
            # If system has rack info in description but no rack_id, it's orphaned
            if metadata['rack']:
                orphaned.append({
                    'system_id': system['id'],
                    'system_name': system['name'],
                    'metadata': metadata
                })
        
        return orphaned

def create_missing_racks(orphaned_systems):
    """Create missing racks and link systems to them"""
    with get_db_connection() as conn:
        rack_cache = {}  # Cache created racks to avoid duplicates
        updates = []
        
        print("\nProcessing orphaned systems...\n")
        print("="*80)
        
        for item in orphaned_systems:
            system_id = item['system_id']
            system_name = item['system_name']
            metadata = item['metadata']
            rack_name = metadata['rack']
            
            print(f"\nSystem: {system_name}")
            print(f"  Rack in metadata: {rack_name}")
            
            # Check if rack already exists
            existing_rack = conn.execute(
                'SELECT id, name, location, room FROM racks WHERE name = ?',
                (rack_name,)
            ).fetchone()
            
            if existing_rack:
                rack_id = existing_rack['id']
                print(f"  ✓ Rack exists: {rack_name} (ID: {rack_id})")
                print(f"    Location: {existing_rack['location']}")
                print(f"    Room: {existing_rack['room']}")
            else:
                # Create the rack if not in cache
                if rack_name not in rack_cache:
                    # Determine location
                    if metadata['geo'] and metadata['building']:
                        location = f"{metadata['geo']} - {metadata['building']}"
                    else:
                        location = "Redmond - Building 50"  # Default
                    
                    # Determine room
                    room = metadata['room']
                    if not room and metadata['hostname']:
                        room = extract_room_from_hostname(metadata['hostname'])
                    if not room:
                        room = "Room 2045"  # Default
                    
                    # Determine rack type
                    rack_type = 'bench' if 'bench' in rack_name.lower() else 'rack'
                    
                    # Create rack
                    cursor = conn.execute('''
                        INSERT INTO racks (name, location, room, rack_type)
                        VALUES (?, ?, ?, ?)
                    ''', (rack_name, location, room, rack_type))
                    rack_id = cursor.lastrowid
                    rack_cache[rack_name] = rack_id
                    
                    print(f"  ✓ Created rack: {rack_name} (ID: {rack_id})")
                    print(f"    Location: {location}")
                    print(f"    Room: {room}")
                    print(f"    Type: {rack_type}")
                else:
                    rack_id = rack_cache[rack_name]
                    print(f"  ✓ Using cached rack: {rack_name} (ID: {rack_id})")
            
            # Link system to rack
            conn.execute('''
                UPDATE systems
                SET rack_id = ?
                WHERE id = ?
            ''', (rack_id, system_id))
            
            print(f"  ✓ Linked system to rack")
            
            updates.append({
                'system_name': system_name,
                'rack_name': rack_name,
                'rack_id': rack_id
            })
        
        print("\n" + "="*80)
        return updates

def show_summary():
    """Show summary of systems by rack"""
    with get_db_connection() as conn:
        # Count systems without rack_id
        orphaned_count = conn.execute('''
            SELECT COUNT(*) as count
            FROM systems
            WHERE rack_id IS NULL OR rack_id = 0
        ''').fetchone()['count']
        
        # Count all racks with system counts
        racks = conn.execute('''
            SELECT r.name, r.room, COUNT(s.id) as system_count
            FROM racks r
            LEFT JOIN systems s ON r.id = s.rack_id
            GROUP BY r.id
            ORDER BY r.room, r.name
        ''').fetchall()
        
        print("\n" + "="*80)
        print("SUMMARY")
        print("="*80)
        print(f"\nOrphaned systems (no rack_id): {orphaned_count}")
        print(f"Total racks: {len(racks)}")
        
        print("\nRacks with system counts:")
        current_room = None
        for rack in racks:
            room = rack['room'] or '(no room)'
            if room != current_room:
                print(f"\n{room}:")
                current_room = room
            print(f"  {rack['name']}: {rack['system_count']} systems")
        
        print("="*80)

def main():
    print("="*80)
    print("FIX ORPHANED SYSTEMS - CREATE MISSING RACKS")
    print("="*80)
    print("\nThis script will:")
    print("1. Find systems with rack metadata but no rack_id")
    print("2. Create missing rack records")
    print("3. Link systems to their racks")
    print()
    
    try:
        orphaned = find_orphaned_systems()
        
        if not orphaned:
            print("✓ No orphaned systems found - all systems are properly linked!")
            show_summary()
            return 0
        
        print(f"\nFound {len(orphaned)} orphaned system(s):")
        for item in orphaned:
            print(f"  - {item['system_name']} → {item['metadata']['rack']}")
        
        response = input("\nProceed with creating racks and linking systems? (yes/no): ")
        if response.lower() != 'yes':
            print("Operation cancelled.")
            return 1
        
        updates = create_missing_racks(orphaned)
        
        print(f"\n✓ Successfully processed {len(updates)} system(s)")
        
        show_summary()
        
        print("\n✓ All systems are now properly linked to racks!")
        return 0
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    exit(main())
