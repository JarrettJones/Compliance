#!/usr/bin/env python3
"""
Remove "Host FPGA Driver & Tools" from program assignments
This firmware type will remain in database for future use but won't be assigned to any programs
"""
import sqlite3

conn = sqlite3.connect('firmware_checker.db')
cursor = conn.cursor()

print("=== Removing Host FPGA Driver & Tools from Program Assignments ===\n")

# Get the firmware type ID
cursor.execute("SELECT id, name FROM firmware_types WHERE name = 'Host FPGA Driver & Tools'")
fw_type = cursor.fetchone()

if not fw_type:
    print("❌ 'Host FPGA Driver & Tools' not found in database")
    conn.close()
    exit(1)

fw_type_id, fw_type_name = fw_type
print(f"Found firmware type: ID={fw_type_id}, Name='{fw_type_name}'")

# Check current assignments
cursor.execute("""
    SELECT p.name 
    FROM programs p
    JOIN program_firmware_types pft ON p.id = pft.program_id
    WHERE pft.firmware_type_id = ?
""", (fw_type_id,))

programs = [row[0] for row in cursor.fetchall()]

if programs:
    print(f"\n📋 Currently assigned to {len(programs)} program(s):")
    for prog in programs:
        print(f"   - {prog}")
    
    # Remove all assignments
    cursor.execute("DELETE FROM program_firmware_types WHERE firmware_type_id = ?", (fw_type_id,))
    conn.commit()
    
    print(f"\n✅ Removed 'Host FPGA Driver & Tools' from all program assignments")
    print("   (Firmware type still exists in database for future use)")
else:
    print("\n✅ No assignments found - already clean")

# Verify removal
cursor.execute("""
    SELECT COUNT(*) 
    FROM program_firmware_types 
    WHERE firmware_type_id = ?
""", (fw_type_id,))

remaining = cursor.fetchone()[0]
if remaining == 0:
    print("\n✓ Verification: No assignments remain")
else:
    print(f"\n⚠️  Warning: {remaining} assignment(s) still exist!")

conn.close()

print("\n" + "="*60)
print("Done! Users will no longer see 'Host FPGA Driver & Tools' as an option.")
print("When implementation is ready, run assign_implemented_types.py to re-enable it.")
