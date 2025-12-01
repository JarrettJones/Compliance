"""
Update rack room numbers by extracting from system hostnames
Hostname pattern: C41431157B0234B where 1157 is the room number
"""
import sqlite3
import re
from contextlib import contextmanager
from collections import defaultdict

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

def extract_room_from_hostname(hostname):
    """
    Extract room number from hostname pattern like C41431157B0234B
    Pattern: C414 (building?) + 31157 (room?) + B02 (rack?) + 34B (U-height?)
    Actually looking at pattern: C4143 1157 B0234B
    The 4-digit number after C4143 appears to be the room
    """
    if not hostname:
        return None
    
    # Pattern: C4143 followed by 4 digits (room number)
    match = re.search(r'C4143(\d{4})', hostname)
    if match:
        room_num = match.group(1)
        return f"Room {room_num}"
    
    return None

def parse_metadata_from_description(description):
    """Parse metadata from system description"""
    metadata = {
        'hostname': '',
        'room': '',
        'rack': ''
    }
    
    if not description:
        return metadata
    
    parts = description.split('|')
    for part in parts:
        part = part.strip()
        if part.startswith('Host:'):
            metadata['hostname'] = part.replace('Host:', '').strip()
        elif part.startswith('Room:'):
            metadata['room'] = part.replace('Room:', '').strip()
        elif part.startswith('Rack:'):
            metadata['rack'] = part.replace('Rack:', '').strip()
    
    return metadata

def analyze_systems():
    """Analyze systems to determine which room each rack should be in"""
    with get_db_connection() as conn:
        # Get all systems with their rack assignments
        systems = conn.execute('''
            SELECT s.id, s.name, s.description, s.rack_id, r.name as rack_name
            FROM systems s
            LEFT JOIN racks r ON s.rack_id = r.id
            WHERE s.rack_id IS NOT NULL
            ORDER BY r.name, s.name
        ''').fetchall()
        
        # Map rack_id -> set of room numbers found in hostnames
        rack_rooms = defaultdict(set)
        rack_names = {}
        
        print("\nAnalyzing system hostnames...\n")
        print("="*80)
        
        for system in systems:
            metadata = parse_metadata_from_description(system['description'])
            hostname = metadata['hostname']
            room_from_hostname = extract_room_from_hostname(hostname)
            
            if room_from_hostname and system['rack_id']:
                rack_rooms[system['rack_id']].add(room_from_hostname)
                rack_names[system['rack_id']] = system['rack_name']
                
                # Show examples
                if len(rack_rooms[system['rack_id']]) == 1:  # First time seeing this rack
                    print(f"Rack: {system['rack_name']}")
                    print(f"  System: {system['name']}")
                    print(f"  Hostname: {hostname}")
                    print(f"  Extracted Room: {room_from_hostname}")
                    print()
        
        print("="*80)
        print("\nSummary by Rack:")
        print("="*80)
        
        updates = []
        conflicts = []
        
        for rack_id, rooms in rack_rooms.items():
            rack_name = rack_names[rack_id]
            if len(rooms) == 1:
                room = list(rooms)[0]
                print(f"✓ {rack_name}: {room} (consistent)")
                updates.append((rack_id, rack_name, room))
            else:
                print(f"⚠ {rack_name}: Multiple rooms found: {', '.join(sorted(rooms))}")
                conflicts.append((rack_id, rack_name, rooms))
        
        print("="*80)
        
        return updates, conflicts

def update_rack_rooms(updates):
    """Update rack room numbers"""
    with get_db_connection() as conn:
        print("\nUpdating rack room numbers...\n")
        
        for rack_id, rack_name, room in updates:
            # Get current room
            current = conn.execute('SELECT room FROM racks WHERE id = ?', (rack_id,)).fetchone()
            current_room = current['room'] if current else None
            
            if current_room != room:
                conn.execute('''
                    UPDATE racks
                    SET room = ?
                    WHERE id = ?
                ''', (room, rack_id))
                print(f"  {rack_name}: '{current_room}' → '{room}'")
            else:
                print(f"  {rack_name}: Already set to '{room}'")
        
        print(f"\n✓ Updated {len(updates)} racks")

def show_final_state():
    """Show final rack room assignments"""
    with get_db_connection() as conn:
        racks = conn.execute('''
            SELECT name, location, room, rack_type
            FROM racks
            ORDER BY room, name
        ''').fetchall()
        
        print("\n" + "="*80)
        print("FINAL RACK ROOM ASSIGNMENTS")
        print("="*80)
        
        current_room = None
        for rack in racks:
            room = rack['room'] or '(no room)'
            if room != current_room:
                print(f"\n{room}:")
                current_room = room
            print(f"  - {rack['name']} ({rack['rack_type']}) at {rack['location']}")
        
        print("="*80)

def main():
    print("="*80)
    print("UPDATE RACK ROOMS FROM SYSTEM HOSTNAMES")
    print("="*80)
    print("\nThis script will:")
    print("1. Analyze system hostnames to extract room numbers")
    print("2. Group systems by rack to determine each rack's room")
    print("3. Update rack room assignments")
    print("4. Report any conflicts (racks with systems in multiple rooms)")
    print()
    
    try:
        # Analyze systems
        updates, conflicts = analyze_systems()
        
        if conflicts:
            print("\n⚠ WARNING: Some racks have systems in multiple rooms:")
            for rack_id, rack_name, rooms in conflicts:
                print(f"  {rack_name}: {', '.join(sorted(rooms))}")
            print("\nThese will need manual review.")
        
        if not updates:
            print("\n✓ No updates needed - all racks already have correct room assignments")
            return 0
        
        print(f"\nReady to update {len(updates)} rack(s)")
        response = input("Proceed with updates? (yes/no): ")
        
        if response.lower() != 'yes':
            print("Update cancelled.")
            return 1
        
        update_rack_rooms(updates)
        show_final_state()
        
        print("\n✓ Room assignments updated successfully!")
        
        return 0
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    exit(main())
