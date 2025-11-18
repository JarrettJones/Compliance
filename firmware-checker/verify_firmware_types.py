import sqlite3

def verify_all_firmware_types():
    """Verify all firmware type names match what the checker code expects"""
    conn = sqlite3.connect('firmware_checker.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Expected firmware types from checker code
    expected_types = {
        'DC-SCM': [
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
            'SCM-CPLD'
        ],
        'OVL2': [
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
        ],
        'Other Platform': [
            'HPMCpld',
            'SOC VR Configs',
            'E.1s',
            'M.2',
            'Windows OS Version'
        ]
    }
    
    print("\n" + "="*80)
    print("FIRMWARE TYPE VERIFICATION")
    print("="*80)
    
    all_correct = True
    
    for category, expected_names in expected_types.items():
        print(f"\n{'='*80}")
        print(f"{category} ({len(expected_names)} expected types)")
        print(f"{'='*80}")
        
        # Get actual types from database
        db_types = cursor.execute("""
            SELECT name FROM firmware_types 
            WHERE category = ? 
            ORDER BY name
        """, (category,)).fetchall()
        db_names = set([row['name'] for row in db_types])
        expected_names_set = set(expected_names)
        
        # Check for missing types
        missing = expected_names_set - db_names
        if missing:
            print(f"\n⚠️  MISSING in database ({len(missing)}):")
            for name in sorted(missing):
                print(f"   - {name}")
                all_correct = False
        
        # Check for extra/incorrect types
        extra = db_names - expected_names_set
        if extra:
            print(f"\n⚠️  EXTRA/INCORRECT in database ({len(extra)}):")
            for name in sorted(extra):
                print(f"   - {name}")
                all_correct = False
        
        # Show correct types
        correct = db_names & expected_names_set
        if correct:
            print(f"\n✅ CORRECT in database ({len(correct)}):")
            for name in sorted(correct):
                print(f"   ✓ {name}")
    
    print(f"\n{'='*80}")
    if all_correct:
        print("✅ ALL FIRMWARE TYPES ARE CORRECT!")
    else:
        print("⚠️  ISSUES FOUND - Run fix script to correct")
    print("="*80)
    
    conn.close()

if __name__ == "__main__":
    verify_all_firmware_types()
