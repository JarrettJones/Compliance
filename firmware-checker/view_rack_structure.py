"""
Quick script to view the rack → RSCM → systems relationships
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
    finally:
        conn.close()

def view_rack_structure():
    """Display the rack structure with RSCMs and systems"""
    with get_db_connection() as conn:
        # Get all racks with their RSCMs and systems
        racks = conn.execute('SELECT * FROM racks ORDER BY name').fetchall()
        
        print("\n" + "="*80)
        print("RACK STRUCTURE")
        print("="*80)
        
        for rack in racks:
            print(f"\n📦 {rack['name']} ({rack['rack_type'].upper()})")
            print(f"   Location: {rack['location']}")
            
            # Get RSCMs for this rack
            rscms = conn.execute('''
                SELECT * FROM rscm_components 
                WHERE rack_id = ? 
                ORDER BY name
            ''', (rack['id'],)).fetchall()
            
            print(f"   RSCMs: {len(rscms)}")
            for rscm in rscms:
                print(f"      🔌 {rscm['name']}: {rscm['ip_address']}:{rscm['port']}")
                
                # Get systems using this RSCM
                systems = conn.execute('''
                    SELECT id, name FROM systems 
                    WHERE rscm_component_id = ?
                    ORDER BY name
                ''', (rscm['id'],)).fetchall()
                
                print(f"         Systems ({len(systems)}):")
                for sys in systems:
                    print(f"            💻 {sys['name']} (ID: {sys['id']})")
            
            # Check for systems in this rack without RSCM component assignment
            orphaned = conn.execute('''
                SELECT id, name, rscm_ip, rscm_port FROM systems 
                WHERE rack_id = ? AND rscm_component_id IS NULL
                ORDER BY name
            ''', (rack['id'],)).fetchall()
            
            if orphaned:
                print(f"   ⚠️  Systems without RSCM component assignment: {len(orphaned)}")
                for sys in orphaned:
                    print(f"      💻 {sys['name']} (uses {sys['rscm_ip']}:{sys['rscm_port']})")
        
        # Summary statistics
        print("\n" + "="*80)
        print("SUMMARY")
        print("="*80)
        
        total_racks = conn.execute('SELECT COUNT(*) as count FROM racks').fetchone()['count']
        total_rscms = conn.execute('SELECT COUNT(*) as count FROM rscm_components').fetchone()['count']
        total_systems = conn.execute('SELECT COUNT(*) as count FROM systems').fetchone()['count']
        linked_systems = conn.execute('SELECT COUNT(*) as count FROM systems WHERE rack_id IS NOT NULL').fetchone()['count']
        
        print(f"Total Racks: {total_racks}")
        print(f"Total RSCM Components: {total_rscms}")
        print(f"Total Systems: {total_systems}")
        print(f"Systems linked to racks: {linked_systems}/{total_systems}")
        
        # Show rack types
        rack_types = conn.execute('''
            SELECT rack_type, COUNT(*) as count 
            FROM racks 
            GROUP BY rack_type
        ''').fetchall()
        
        print("\nRack Types:")
        for rt in rack_types:
            print(f"  {rt['rack_type']}: {rt['count']}")

if __name__ == '__main__':
    view_rack_structure()
