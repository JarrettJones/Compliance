#!/usr/bin/env python3
"""
Remove extra OVL2 firmware types that don't have implementations.
Keep only the 12 types that exist in ovl2.py checker code.
"""
import sqlite3

# These are the ONLY OVL2 types that should exist (from ovl2.py)
KEEP_OVL2_TYPES = [
    'FPGA Agilex (App Image w/ OpRom)',
    'Cyclone V Image',
    'Cyclone V PFMID',
    'OVL SOC FIP',
    'OVL SOC FIP PFMID',
    'SOC Test OS (STOS)',
    'Host FPGA Driver & Tools',
    'SOC FPGA Driver',
    'MANA Driver (Windows)',
    'Glacier Cerberus FW',
    'Glacier Cerberus Utility',
    'Glacier Peak CFM'
]

conn = sqlite3.connect('firmware_checker.db')
cursor = conn.cursor()

print("=== Removing Extra OVL2 Firmware Types ===\n")

# Get all current OVL2 types
cursor.execute("SELECT id, name FROM firmware_types WHERE category = 'OVL2' ORDER BY name")
current_types = cursor.fetchall()

to_remove = []
to_keep = []

for fw_id, name in current_types:
    if name not in KEEP_OVL2_TYPES:
        to_remove.append((fw_id, name))
    else:
        to_keep.append((fw_id, name))

if to_remove:
    print(f"🗑️  Removing {len(to_remove)} extra OVL2 types:\n")
    for fw_id, name in to_remove:
        print(f"   ID {fw_id}: {name}")
        # Remove from program assignments first
        cursor.execute("DELETE FROM program_firmware_types WHERE firmware_type_id = ?", (fw_id,))
        # Remove the firmware type
        cursor.execute("DELETE FROM firmware_types WHERE id = ?", (fw_id,))
    
    conn.commit()
    print(f"\n✅ Removed {len(to_remove)} firmware types")
else:
    print("✅ No extra types to remove")

print(f"\n📊 Keeping {len(to_keep)} OVL2 types:")
for fw_id, name in sorted(to_keep, key=lambda x: x[1]):
    print(f"   ID {fw_id}: {name}")

conn.close()

print("\n" + "="*60)
print(f"✅ OVL2 firmware types cleaned up!")
print(f"Database now has exactly {len(KEEP_OVL2_TYPES)} OVL2 types.")
