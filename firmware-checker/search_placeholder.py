#!/usr/bin/env python3

import sqlite3
import json

def main():
    conn = sqlite3.connect('firmware_checker.db')
    cursor = conn.cursor()
    
    # Get all checks
    cursor.execute('SELECT id, firmware_data FROM firmware_checks')
    all_checks = cursor.fetchall()
    
    placeholder_found = []
    total_items_checked = 0
    
    print(f"Scanning {len(all_checks)} firmware checks for placeholder status...")
    
    for check_id, firmware_data in all_checks:
        if not firmware_data:
            continue
            
        try:
            data = json.loads(firmware_data)
            
            for platform in ['dc_scm', 'ovl2', 'other_platform']:
                if platform in data and 'firmware_versions' in data[platform]:
                    for fw_name, fw_data in data[platform]['firmware_versions'].items():
                        total_items_checked += 1
                        status = fw_data.get('status')
                        if status == 'placeholder':
                            placeholder_found.append((check_id, platform, fw_name, fw_data.get('version', 'N/A')))
        except json.JSONDecodeError:
            print(f"  Warning: Check {check_id} has invalid JSON data")
        except Exception as e:
            print(f"  Warning: Check {check_id} processing error: {e}")
    
    print(f"\nResults:")
    print(f"  Total firmware items scanned: {total_items_checked}")
    print(f"  Items with 'placeholder' status: {len(placeholder_found)}")
    
    if placeholder_found:
        print(f"\nPlaceholder items found:")
        for check_id, platform, fw_name, version in placeholder_found:
            print(f"  Check {check_id}: {platform}.{fw_name} = {version}")
    else:
        print(f"\nNo items with 'placeholder' status found in database!")
        
        # Show status distribution for most recent check
        cursor.execute('SELECT id, firmware_data FROM firmware_checks ORDER BY id DESC LIMIT 1')
        recent_check = cursor.fetchone()
        
        if recent_check:
            check_id, firmware_data = recent_check
            data = json.loads(firmware_data)
            status_counts = {}
            
            print(f"\nStatus distribution for most recent check (ID {check_id}):")
            
            for platform in ['dc_scm', 'ovl2', 'other_platform']:
                if platform in data and 'firmware_versions' in data[platform]:
                    for fw_name, fw_data in data[platform]['firmware_versions'].items():
                        status = fw_data.get('status', 'unknown')
                        status_counts[status] = status_counts.get(status, 0) + 1
            
            for status, count in sorted(status_counts.items()):
                print(f"  {status}: {count} items")
    
    conn.close()

if __name__ == "__main__":
    main()