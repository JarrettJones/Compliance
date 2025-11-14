import sqlite3
import sys

def assign_all_firmware_types_to_program(program_id):
    """Assign all available firmware types to a specific program"""
    conn = sqlite3.connect('firmware_checker.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get program info
    program = cursor.execute("SELECT * FROM programs WHERE id = ?", (program_id,)).fetchone()
    if not program:
        print(f"❌ Error: Program ID {program_id} not found!")
        conn.close()
        return
    
    print(f"\n📋 Program: {program['name']} (ID: {program_id})")
    
    # Get all firmware types
    firmware_types = cursor.execute("SELECT * FROM firmware_types ORDER BY category, name").fetchall()
    print(f"📦 Found {len(firmware_types)} total firmware types in database")
    
    # Check what's already assigned
    existing = cursor.execute("""
        SELECT firmware_type_id FROM program_firmware_types WHERE program_id = ?
    """, (program_id,)).fetchall()
    existing_ids = set([row['firmware_type_id'] for row in existing])
    
    print(f"✓ Already assigned: {len(existing_ids)} types")
    
    # Assign all firmware types to this program
    added = 0
    for ft in firmware_types:
        if ft['id'] not in existing_ids:
            cursor.execute("""
                INSERT INTO program_firmware_types (program_id, firmware_type_id)
                VALUES (?, ?)
            """, (program_id, ft['id']))
            added += 1
    
    conn.commit()
    
    print(f"✅ Added {added} new firmware type assignments")
    print(f"✓ Total firmware types now assigned to '{program['name']}': {len(existing_ids) + added}")
    
    # Show breakdown by category
    assigned_types = cursor.execute("""
        SELECT ft.category, COUNT(*) as count
        FROM firmware_types ft
        INNER JOIN program_firmware_types pft ON ft.id = pft.firmware_type_id
        WHERE pft.program_id = ?
        GROUP BY ft.category
        ORDER BY ft.category
    """, (program_id,)).fetchall()
    
    print("\n📊 Breakdown by category:")
    for row in assigned_types:
        print(f"   {row['category']}: {row['count']} types")
    
    conn.close()
    print("\n✅ Done! Firmware types successfully assigned to program.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python assign_firmware_types_to_program.py <program_id>")
        print("\nExample: python assign_firmware_types_to_program.py 1")
        sys.exit(1)
    
    try:
        program_id = int(sys.argv[1])
        assign_all_firmware_types_to_program(program_id)
    except ValueError:
        print("❌ Error: Program ID must be a number")
        sys.exit(1)
