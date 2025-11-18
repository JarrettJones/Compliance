import sqlite3

conn = sqlite3.connect('firmware_checker.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Check if this firmware type exists
result = cursor.execute("""
    SELECT id, category, name 
    FROM firmware_types 
    WHERE name LIKE '%Host FPGA%'
""").fetchall()

print("\n=== Host FPGA Firmware Types ===")
if result:
    for row in result:
        print(f"ID: {row['id']}, Category: {row['category']}, Name: {row['name']}")
        
        # Check if assigned to Echo Falls
        assigned = cursor.execute("""
            SELECT p.name 
            FROM program_firmware_types pft
            JOIN programs p ON pft.program_id = p.id
            WHERE pft.firmware_type_id = ?
        """, (row['id'],)).fetchall()
        
        if assigned:
            print(f"  Assigned to programs: {', '.join([p['name'] for p in assigned])}")
        else:
            print(f"  ⚠️  NOT assigned to any program")
else:
    print("Not found in database")

# Check exact name match
exact = cursor.execute("""
    SELECT * FROM firmware_types WHERE name = 'Host FPGA Driver & Tools'
""").fetchone()

print(f"\n=== Exact Match: 'Host FPGA Driver & Tools' ===")
if exact:
    print(f"✓ Found: ID={exact['id']}, Category={exact['category']}")
else:
    print("✗ Not found")

conn.close()
