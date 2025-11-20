"""
Migration script to create racks table and migrate existing systems to use racks
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

def create_tables():
    """Create the new racks and rscm_components tables"""
    with get_db_connection() as conn:
        # Create racks table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS racks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                location TEXT NOT NULL DEFAULT 'Redmond, WA - Building 50',
                rack_type TEXT DEFAULT 'rack',
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT valid_rack_type CHECK (rack_type IN ('rack', 'bench'))
            )
        ''')
        
        # Create RSCM components table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS rscm_components (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rack_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 22,
                position TEXT,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(rack_id, ip_address, port),
                FOREIGN KEY (rack_id) REFERENCES racks (id) ON DELETE CASCADE
            )
        ''')
        
        # Add new columns to systems table if they don't exist
        try:
            conn.execute('ALTER TABLE systems ADD COLUMN rack_id INTEGER REFERENCES racks(id)')
            print("✓ Added rack_id column to systems table")
        except sqlite3.OperationalError as e:
            if 'duplicate column name' in str(e):
                print("  rack_id column already exists")
            else:
                raise
        
        try:
            conn.execute('ALTER TABLE systems ADD COLUMN rscm_component_id INTEGER REFERENCES rscm_components(id)')
            print("✓ Added rscm_component_id column to systems table")
        except sqlite3.OperationalError as e:
            if 'duplicate column name' in str(e):
                print("  rscm_component_id column already exists")
            else:
                raise
        
        print("\n✓ Tables created successfully")

def parse_rack_from_description(description):
    """Extract rack name from description field"""
    if not description:
        return None
    
    # Look for "Rack: <name>" pattern
    match = re.search(r'Rack:\s*([^|]+)', description)
    if match:
        return match.group(1).strip()
    
    return None

def parse_geo_from_description(description):
    """Extract geo location from description field"""
    if not description:
        return None
    
    # Look for "Geo: <location>" pattern
    match = re.search(r'Geo:\s*([^|]+)', description)
    if match:
        return match.group(1).strip()
    
    return None

def migrate_data():
    """Migrate existing systems to use racks"""
    with get_db_connection() as conn:
        # Get all systems
        systems = conn.execute('SELECT * FROM systems').fetchall()
        
        print(f"\nProcessing {len(systems)} systems...")
        
        rack_map = {}  # Track created racks: {rack_name: rack_id}
        rscm_map = {}  # Track created RSCMs: {(rack_id, ip): rscm_id} - NOTE: IP only, not port!
        
        for system in systems:
            system_id = system['id']
            system_name = system['name']
            description = system['description']
            rscm_ip = system['rscm_ip']
            rscm_port = system['rscm_port']
            
            # Extract rack name from description
            rack_name = parse_rack_from_description(description)
            geo_location = parse_geo_from_description(description)
            
            if not rack_name:
                # Try to extract from system name if not in description
                # Common patterns: "SystemName-R42", "R42-SystemName", etc.
                match = re.search(r'(?:^|-)([A-Z]\d+)(?:-|$)', system_name)
                if match:
                    rack_name = match.group(1)
                else:
                    print(f"  ⚠ System '{system_name}' - No rack found, skipping for manual review")
                    continue
            
            # Determine location - use geo if available, otherwise default
            if geo_location:
                location = f"{geo_location} - Building 50"
            else:
                location = "Redmond, WA - Building 50"
            
            # Create or get rack
            if rack_name not in rack_map:
                try:
                    cursor = conn.execute('''
                        INSERT INTO racks (name, location, rack_type)
                        VALUES (?, ?, 'rack')
                    ''', (rack_name, location))
                    rack_id = cursor.lastrowid
                    rack_map[rack_name] = rack_id
                    print(f"  ✓ Created rack: {rack_name} in {location}")
                except sqlite3.IntegrityError:
                    # Rack already exists
                    rack_id = conn.execute('SELECT id FROM racks WHERE name = ?', (rack_name,)).fetchone()['id']
                    rack_map[rack_name] = rack_id
            else:
                rack_id = rack_map[rack_name]
            
            # Create or get RSCM component (by IP only, not port!)
            # Each physical RSCM has one IP, servers connect via different ports
            rscm_key = (rack_id, rscm_ip)
            if rscm_key not in rscm_map:
                try:
                    # Determine RSCM name based on how many unique IPs in this rack
                    rscm_count = conn.execute(
                        'SELECT COUNT(*) as count FROM rscm_components WHERE rack_id = ?',
                        (rack_id,)
                    ).fetchone()['count']
                    
                    if rscm_count == 0:
                        rscm_name = "RSCM-Upper"
                    elif rscm_count == 1:
                        rscm_name = "RSCM-Lower"
                    else:
                        rscm_name = f"RSCM-{rscm_count + 1}"
                    
                    cursor = conn.execute('''
                        INSERT INTO rscm_components (rack_id, name, ip_address, port)
                        VALUES (?, ?, ?, ?)
                    ''', (rack_id, rscm_name, rscm_ip, 22))  # Default port 22, actual port stored in systems table
                    rscm_id = cursor.lastrowid
                    rscm_map[rscm_key] = rscm_id
                    print(f"    ✓ Created RSCM: {rscm_name} ({rscm_ip})")
                except sqlite3.IntegrityError:
                    # RSCM already exists (shouldn't happen but handle it)
                    rscm_id = conn.execute('''
                        SELECT id FROM rscm_components 
                        WHERE rack_id = ? AND ip_address = ?
                    ''', (rack_id, rscm_ip)).fetchone()['id']
                    rscm_map[rscm_key] = rscm_id
            else:
                rscm_id = rscm_map[rscm_key]
            
            # Update system with rack and RSCM component references
            # Note: system.rscm_port stays in systems table showing which port this server uses
            conn.execute('''
                UPDATE systems 
                SET rack_id = ?, rscm_component_id = ?
                WHERE id = ?
            ''', (rack_id, rscm_id, system_id))
            
            print(f"  ✓ Linked system '{system_name}' to {rack_name} (via {rscm_ip}:{rscm_port})")
        
        print(f"\n✓ Migration complete!")
        print(f"  - Created {len(rack_map)} racks")
        print(f"  - Created {len(rscm_map)} RSCM components (physical units)")
        print(f"  - Updated {len(systems)} systems")

def print_summary():
    """Print summary of migration"""
    with get_db_connection() as conn:
        rack_count = conn.execute('SELECT COUNT(*) as count FROM racks').fetchone()['count']
        rscm_count = conn.execute('SELECT COUNT(*) as count FROM rscm_components').fetchone()['count']
        linked_systems = conn.execute('SELECT COUNT(*) as count FROM systems WHERE rack_id IS NOT NULL').fetchone()['count']
        total_systems = conn.execute('SELECT COUNT(*) as count FROM systems').fetchone()['count']
        
        print("\n" + "="*60)
        print("MIGRATION SUMMARY")
        print("="*60)
        print(f"Total Racks: {rack_count}")
        print(f"Total RSCM Components: {rscm_count}")
        print(f"Systems linked to racks: {linked_systems}/{total_systems}")
        
        if linked_systems < total_systems:
            print(f"\n⚠ {total_systems - linked_systems} systems need manual rack assignment")
            unlinked = conn.execute('SELECT id, name, description FROM systems WHERE rack_id IS NULL').fetchall()
            print("\nUnlinked systems:")
            for sys in unlinked:
                print(f"  - {sys['name']} (ID: {sys['id']})")
                if sys['description']:
                    print(f"    Description: {sys['description']}")

def main():
    print("="*60)
    print("RACKS MIGRATION SCRIPT")
    print("="*60)
    print("\nThis will:")
    print("1. Create racks and rscm_components tables")
    print("2. Parse existing system descriptions to extract rack names")
    print("3. Create rack entries with default location: Redmond, WA - Building 50")
    print("4. Create RSCM component entries")
    print("5. Link systems to racks and RSCMs")
    print("\nNote: Existing rscm_ip and rscm_port fields will be preserved for backward compatibility")
    
    response = input("\nProceed with migration? (yes/no): ")
    if response.lower() != 'yes':
        print("Migration cancelled.")
        return
    
    print("\nStarting migration...\n")
    
    try:
        create_tables()
        migrate_data()
        print_summary()
        
        print("\n✓ Migration completed successfully!")
        print("\nNext steps:")
        print("1. Review any unlinked systems and manually assign them to racks")
        print("2. Review rack locations and update if needed")
        print("3. Designate any bench systems using the UI")
        
    except Exception as e:
        print(f"\n✗ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == '__main__':
    exit(main())
