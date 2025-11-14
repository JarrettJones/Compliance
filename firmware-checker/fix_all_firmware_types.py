import sqlite3

def fix_all_firmware_types():
    """Fix all firmware type names and add missing ones"""
    conn = sqlite3.connect('firmware_checker.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    print("\n" + "="*80)
    print("FIXING ALL FIRMWARE TYPE ISSUES")
    print("="*80)
    
    # 1. Add missing DC-SCM type
    print("\n--- DC-SCM ---")
    missing_dc_scm = [
        ('DC-SCM', 'UEFI Profile/Other', 'UEFI Profile/Other')
    ]
    
    for category, name, desc in missing_dc_scm:
        existing = cursor.execute("SELECT id FROM firmware_types WHERE name = ?", (name,)).fetchone()
        if not existing:
            cursor.execute("INSERT INTO firmware_types (category, name, description) VALUES (?, ?, ?)",
                         (category, name, desc))
            print(f"✅ Added: {name}")
        else:
            print(f"   Already exists: {name}")
    
    # 2. Remove extra OVL2 types (these are not in the checker code)
    print("\n--- OVL2 ---")
    extra_ovl2 = [
        'Cyclone V PFM Platform ID',
        'FPGA Agilex (Sonic Basic)',
        'FPGAsec Tool',
        'OVL SOC FIP PFM Platform ID',
        'OVL2 (overall package #)',
        'SOC FPGA Tools'
    ]
    
    for name in extra_ovl2:
        result = cursor.execute("SELECT id FROM firmware_types WHERE name = ?", (name,)).fetchone()
        if result:
            # Remove from program associations first
            cursor.execute("DELETE FROM program_firmware_types WHERE firmware_type_id = ?", (result['id'],))
            # Remove the type
            cursor.execute("DELETE FROM firmware_types WHERE id = ?", (result['id'],))
            print(f"🗑️  Removed: {name}")
        else:
            print(f"   Not found: {name}")
    
    # 3. Fix Other Platform types
    print("\n--- Other Platform ---")
    
    # Remove the incorrectly named types
    incorrect_other = [
        'E.1s (Secondary)',
        'E.1s(primary)',
        'M.2(Primary)',
        'M.2(Secondary)'
    ]
    
    for name in incorrect_other:
        result = cursor.execute("SELECT id FROM firmware_types WHERE name = ?", (name,)).fetchone()
        if result:
            cursor.execute("DELETE FROM program_firmware_types WHERE firmware_type_id = ?", (result['id'],))
            cursor.execute("DELETE FROM firmware_types WHERE id = ?", (result['id'],))
            print(f"🗑️  Removed: {name}")
    
    # Add the correct types
    missing_other = [
        ('Other Platform', 'E.1s', 'E.1s Storage'),
        ('Other Platform', 'M.2', 'M.2 Storage'),
        ('Other Platform', 'Windows OS Version', 'Windows OS Version')
    ]
    
    for category, name, desc in missing_other:
        existing = cursor.execute("SELECT id FROM firmware_types WHERE name = ?", (name,)).fetchone()
        if not existing:
            cursor.execute("INSERT INTO firmware_types (category, name, description) VALUES (?, ?, ?)",
                         (category, name, desc))
            print(f"✅ Added: {name}")
        else:
            print(f"   Already exists: {name}")
    
    conn.commit()
    
    print("\n" + "="*80)
    print("✅ ALL FIXES APPLIED")
    print("="*80)
    
    # Show summary by category
    print("\n📊 SUMMARY:")
    for category in ['DC-SCM', 'OVL2', 'Other Platform']:
        count = cursor.execute("""
            SELECT COUNT(*) as count FROM firmware_types WHERE category = ?
        """, (category,)).fetchone()['count']
        print(f"   {category}: {count} types")
    
    conn.close()
    
    print("\n✅ Done! Now re-assign firmware types to your program:")
    print("   python assign_implemented_types.py")

if __name__ == "__main__":
    fix_all_firmware_types()
