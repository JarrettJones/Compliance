"""
Quick script to assign ALL firmware types to Echo Falls program
Run this to enable all checks for Echo Falls
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

# Get all firmware types grouped by category
categories = cursor.execute("""
    SELECT DISTINCT category FROM firmware_types ORDER BY category
""").fetchall()

print(f"\nAssigning firmware types from {len(categories)} categories:")

total_assigned = 0
for category in categories:
    cat_name = category[0]
    fw_types = cursor.execute("""
        SELECT id, name FROM firmware_types WHERE category = ?
    """, (cat_name,)).fetchall()
    
    print(f"\n{cat_name} ({len(fw_types)} types):")
    
    for fw_type in fw_types:
        try:
            cursor.execute("""
                INSERT INTO program_firmware_types (program_id, firmware_type_id)
                VALUES (?, ?)
            """, (program_id, fw_type[0]))
            print(f"  ✓ {fw_type[1]}")
            total_assigned += 1
        except sqlite3.IntegrityError:
            print(f"  - {fw_type[1]} (already assigned)")

conn.commit()

# Show summary
final_count = cursor.execute("""
    SELECT COUNT(*) FROM program_firmware_types WHERE program_id = ?
""", (program_id,)).fetchone()[0]

print(f"\n{'='*60}")
print(f"✅ Total firmware types assigned to Echo Falls: {final_count}")
print(f"   (Added {total_assigned} new assignments)")
print(f"{'='*60}")

conn.close()
