"""
Quick script to assign all OVL2 firmware types to Echo Falls program
Run this to test the firmware type association feature
"""
import sqlite3

# Connect to database
conn = sqlite3.connect('firmware_checker.db')
cursor = conn.cursor()

# Get Echo Falls program ID
program = cursor.execute("SELECT id, name FROM programs WHERE name = 'Echo Falls'").fetchone()
if not program:
    print("Echo Falls program not found!")
    conn.close()
    exit(1)

program_id = program[0]
print(f"Found program: {program[1]} (ID: {program_id})")

# Get all OVL2 firmware types
ovl2_types = cursor.execute("""
    SELECT id, name, category FROM firmware_types WHERE category = 'OVL2'
""").fetchall()

print(f"\nFound {len(ovl2_types)} OVL2 firmware types")

# Assign them to Echo Falls
for fw_type in ovl2_types:
    try:
        cursor.execute("""
            INSERT INTO program_firmware_types (program_id, firmware_type_id)
            VALUES (?, ?)
        """, (program_id, fw_type[0]))
        print(f"  ✓ Assigned: {fw_type[1]}")
    except sqlite3.IntegrityError:
        print(f"  - Already assigned: {fw_type[1]}")

conn.commit()

# Show summary
assigned = cursor.execute("""
    SELECT COUNT(*) FROM program_firmware_types WHERE program_id = ?
""", (program_id,)).fetchone()[0]

print(f"\n✅ Total firmware types assigned to Echo Falls: {assigned}")

conn.close()
