import sqlite3

def fix_firmware_type_names():
    """Fix firmware type names in database to match what the checker code expects"""
    conn = sqlite3.connect('firmware_checker.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Mapping of incorrect names to correct names
    name_fixes = {
        'BMC': 'BMC FW',
        'BMCTip': 'BMC Tip',
        'BMCTip PCD Platform ID': 'BMC TIP PCD Platform ID',
        'BMCTip PCD Version': 'BMC TIP PCD Version ID (hex)/(dec)',
        'CFM PlatformID': 'CFM Platform ID',
        'CFMVersion ID': 'CFM Version ID (hex)/(dec)',
        'Manticore': 'Manticore (HSM)',
    }
    
    print("\n📝 Fixing firmware type names to match checker code...\n")
    
    fixed_count = 0
    for old_name, new_name in name_fixes.items():
        # Check if old name exists
        result = cursor.execute("SELECT id, name FROM firmware_types WHERE name = ?", (old_name,)).fetchone()
        if result:
            # Check if new name already exists
            existing_new = cursor.execute("SELECT id FROM firmware_types WHERE name = ?", (new_name,)).fetchone()
            
            if existing_new:
                print(f"⚠️  '{old_name}' → '{new_name}' (new name already exists, will merge)")
                # New name exists - need to update references and delete old
                old_id = result['id']
                new_id = existing_new['id']
                
                # Update program_firmware_types references
                cursor.execute("""
                    UPDATE program_firmware_types 
                    SET firmware_type_id = ? 
                    WHERE firmware_type_id = ? AND NOT EXISTS (
                        SELECT 1 FROM program_firmware_types 
                        WHERE firmware_type_id = ? AND program_id = program_firmware_types.program_id
                    )
                """, (new_id, old_id, new_id))
                
                # Delete old entry
                cursor.execute("DELETE FROM program_firmware_types WHERE firmware_type_id = ?", (old_id,))
                cursor.execute("DELETE FROM firmware_types WHERE id = ?", (old_id,))
                fixed_count += 1
            else:
                print(f"✓ '{old_name}' → '{new_name}'")
                # Just rename
                cursor.execute("UPDATE firmware_types SET name = ? WHERE id = ?", (new_name, result['id']))
                fixed_count += 1
        else:
            print(f"   '{old_name}' - not found (already correct or doesn't exist)")
    
    conn.commit()
    
    print(f"\n✅ Fixed {fixed_count} firmware type names")
    
    # Show current DC-SCM firmware types
    print("\n📋 Current DC-SCM firmware types in database:")
    dc_scm_types = cursor.execute("""
        SELECT name FROM firmware_types 
        WHERE category = 'DC-SCM' 
        ORDER BY name
    """).fetchall()
    
    for ft in dc_scm_types:
        print(f"   - {ft['name']}")
    
    conn.close()
    print("\n✅ Done! Firmware type names have been corrected.")

if __name__ == "__main__":
    fix_firmware_type_names()
