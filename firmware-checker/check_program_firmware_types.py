import sqlite3

# Connect to the database
conn = sqlite3.connect('firmware_checker.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Check programs
programs = cursor.execute("SELECT * FROM programs").fetchall()
print(f"\n=== Programs ({len(programs)} total) ===")
for program in programs:
    print(f"\nProgram ID: {program['id']}, Name: {program['name']}")
    
    # Check how many firmware types are assigned to this program
    program_fw_types = cursor.execute("""
        SELECT ft.id, ft.name, ft.category 
        FROM firmware_types ft
        INNER JOIN program_firmware_types pft ON ft.id = pft.firmware_type_id
        WHERE pft.program_id = ?
        ORDER BY ft.category, ft.name
    """, (program['id'],)).fetchall()
    
    print(f"  Assigned firmware types: {len(program_fw_types)}")
    if len(program_fw_types) > 0:
        by_category = {}
        for ft in program_fw_types:
            cat = ft['category']
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(ft['name'])
        
        for cat, types in by_category.items():
            print(f"    {cat}: {len(types)} types")
    else:
        print("    ⚠️  No firmware types assigned!")

# Check total firmware types available
total_fw_types = cursor.execute("SELECT COUNT(*) as count FROM firmware_types").fetchone()
print(f"\n=== Total Firmware Types in Database: {total_fw_types['count']} ===")

# Show systems and their programs
systems = cursor.execute("""
    SELECT s.id, s.name, s.program_id, p.name as program_name
    FROM systems s
    LEFT JOIN programs p ON s.program_id = p.id
""").fetchall()

print(f"\n=== Systems ({len(systems)} total) ===")
for system in systems:
    if system['program_id']:
        print(f"  System: {system['name']} -> Program: {system['program_name']} (ID: {system['program_id']})")
    else:
        print(f"  System: {system['name']} -> ⚠️  No program assigned")

conn.close()

print("\n" + "="*60)
print("To assign firmware types to a program, run:")
print("  python assign_firmware_types_to_program.py <program_id>")
print("="*60)
