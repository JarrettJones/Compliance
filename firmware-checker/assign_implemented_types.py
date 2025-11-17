import sqlite3

def assign_implemented_firmware_types():
    """Assign only the firmware types that have proper checking implementations"""
    conn = sqlite3.connect('firmware_checker.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # These are the firmware types that have actual checking implementations
    implemented_types = [
        # DC-SCM - implemented
        'IFWI',
        'UEFI Profile/Other',
        'BMC FW',
        'Inventory',
        'PowerCapping',
        'FanTable',
        'SDRGenerator',
        'IPMIAllowList',
        'BMC Tip',
        'BMC TIP PCD Platform ID',
        'BMC TIP PCD Version ID (hex)/(dec)',
        'Manticore (HSM)',
        'CFM Platform ID',
        'CFM Version ID (hex)/(dec)',
        'TPM Module',
        'SCM-CPLD',
        
        # Other Platform - implemented
        'HPMCpld',
        'SOC VR Configs',
        'E.1s',
        'M.2',
        'Windows OS Version',
        
        # OVL2 - implemented (11 types)
        'FPGA Agilex (App Image w/ OpRom)',
        'Cyclone V Image',
        'Cyclone V PFMID',
        'OVL SOC FIP',
        'OVL SOC FIP PFMID',
        'SOC Test OS (STOS)',
        'SOC FPGA Driver',
        'MANA Driver (Windows)',
        'Glacier Cerberus FW',
        'Glacier Cerberus Utility',
        'Glacier Peak CFM',
        # Note: 'Host FPGA Driver & Tools' removed until implementation is complete
    ]
    
    # Get Echo Falls program
    program = cursor.execute("SELECT * FROM programs WHERE name = 'Echo Falls'").fetchone()
    if not program:
        print("❌ Echo Falls program not found!")
        conn.close()
        return
    
    program_id = program['id']
    print(f"\n📋 Program: {program['name']} (ID: {program_id})")
    
    # Get firmware type IDs for implemented types
    placeholders = ','.join('?' * len(implemented_types))
    firmware_types = cursor.execute(f"""
        SELECT id, name, category 
        FROM firmware_types 
        WHERE name IN ({placeholders})
        ORDER BY category, name
    """, implemented_types).fetchall()
    
    print(f"📦 Found {len(firmware_types)} implemented firmware types")
    
    # Clear existing assignments
    cursor.execute("DELETE FROM program_firmware_types WHERE program_id = ?", (program_id,))
    print("🧹 Cleared old assignments")
    
    # Assign only implemented types
    by_category = {}
    for ft in firmware_types:
        cursor.execute("""
            INSERT INTO program_firmware_types (program_id, firmware_type_id)
            VALUES (?, ?)
        """, (program_id, ft['id']))
        
        cat = ft['category']
        if cat not in by_category:
            by_category[cat] = 0
        by_category[cat] += 1
    
    conn.commit()
    
    print(f"\n✅ Assigned {len(firmware_types)} firmware types to '{program['name']}'")
    print("\n📊 Breakdown by category:")
    for cat, count in sorted(by_category.items()):
        print(f"   {cat}: {count} types")
    
    # Show any firmware types in DB that are NOT implemented
    all_types = cursor.execute("SELECT name, category FROM firmware_types ORDER BY category, name").fetchall()
    unimplemented = [ft for ft in all_types if ft['name'] not in implemented_types]
    
    if unimplemented:
        print(f"\n⚠️  {len(unimplemented)} firmware types in DB are NOT assigned (no implementation):")
        for ft in unimplemented:
            print(f"   - {ft['category']}: {ft['name']}")
    
    conn.close()
    print("\n✅ Done!")

if __name__ == "__main__":
    assign_implemented_firmware_types()
