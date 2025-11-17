#!/usr/bin/env python3
"""
Fix OVL2 firmware type names to match checker code expectations.
The checker code in ovl2.py has specific name expectations.
"""
import sqlite3

# Expected names from ovl2.py self.firmware_types list
EXPECTED_OVL2_TYPES = {
    'FPGA Agilex (App Image w/ OpRom)': 'FPGA Agilex Application Image with Option ROM',
    'Cyclone V Image': 'Cyclone V FPGA Image',
    'Cyclone V PFMID': 'Cyclone V Platform Firmware ID',
    'OVL SOC FIP': 'OVL SOC Firmware Image Package',
    'OVL SOC FIP PFMID': 'OVL SOC FIP Platform Firmware ID',
    'SOC Test OS (STOS)': 'SOC Test Operating System',
    'Host FPGA Driver & Tools': 'Host FPGA Driver and Tools',  # Note: keeping & in DB name, but user sees different display
    'SOC FPGA Driver': 'SOC FPGA Driver',
    'MANA Driver (Windows)': 'MANA Driver for Windows',
    'Glacier Cerberus FW': 'Glacier Cerberus Firmware',
    'Glacier Cerberus Utility': 'Glacier Cerberus Utility',
    'Glacier Peak CFM': 'Glacier Peak Configuration Management'
}

conn = sqlite3.connect('firmware_checker.db')
cursor = conn.cursor()

print("=== Checking Current OVL2 Firmware Types ===\n")
cursor.execute("SELECT id, name FROM firmware_types WHERE category = 'OVL2' ORDER BY name")
current_types = cursor.fetchall()

for fw_id, name in current_types:
    if name in EXPECTED_OVL2_TYPES:
        print(f"✓ ID {fw_id}: '{name}' - OK")
    else:
        print(f"✗ ID {fw_id}: '{name}' - NOT IN EXPECTED LIST")

print(f"\n📊 Total OVL2 types in database: {len(current_types)}")
print(f"📊 Expected OVL2 types: {len(EXPECTED_OVL2_TYPES)}")

# Check if all expected types exist
print("\n=== Verifying All Expected Types Exist ===\n")
existing_names = {name for _, name in current_types}
missing = set(EXPECTED_OVL2_TYPES.keys()) - existing_names
extra = existing_names - set(EXPECTED_OVL2_TYPES.keys())

if missing:
    print("❌ Missing types:")
    for name in sorted(missing):
        print(f"   - {name}")
else:
    print("✅ All expected types exist")

if extra:
    print("\n⚠️  Extra types (not in checker code):")
    for name in sorted(extra):
        print(f"   - {name}")

conn.close()

print("\n" + "="*60)
print("NOTE: Database names must exactly match firmware_modules/ovl2.py")
print("Display names shown to users can be different.")
