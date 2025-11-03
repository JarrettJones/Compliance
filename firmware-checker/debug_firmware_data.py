#!/usr/bin/env python3

import sqlite3
import json

def main():
    # Connect to database
    conn = sqlite3.connect('firmware_checker.db')
    cursor = conn.cursor()
    
    # Get the most recent check
    cursor.execute('SELECT id, firmware_data FROM firmware_checks ORDER BY id DESC LIMIT 1')
    record = cursor.fetchone()
    
    if record:
        check_id, firmware_data = record
        print(f"Examining Check ID: {check_id}")
        
        # Parse the JSON
        firmware_json = json.loads(firmware_data)
        
        # Check DC-SCM firmware items
        print("\nDC-SCM firmware items (first 5):")
        if 'dc_scm' in firmware_json and 'firmware_versions' in firmware_json['dc_scm']:
            dc_scm_items = list(firmware_json['dc_scm']['firmware_versions'].items())[:5]
            for item_name, item_data in dc_scm_items:
                status = item_data.get('status', 'MISSING_STATUS')
                version = item_data.get('version', 'MISSING_VERSION')
                print(f"  {item_name}:")
                print(f"    status: {status}")
                print(f"    version: {version}")
        
        # Check OVL2 firmware items  
        print("\nOVL2 firmware items (first 3):")
        if 'ovl2' in firmware_json and 'firmware_versions' in firmware_json['ovl2']:
            ovl2_items = list(firmware_json['ovl2']['firmware_versions'].items())[:3]
            for item_name, item_data in ovl2_items:
                status = item_data.get('status', 'MISSING_STATUS')
                version = item_data.get('version', 'MISSING_VERSION')
                print(f"  {item_name}:")
                print(f"    status: {status}")
                print(f"    version: {version}")
                
        # Check Other Platform firmware items
        print("\nOther Platform firmware items (first 2):")
        if 'other_platform' in firmware_json and 'firmware_versions' in firmware_json['other_platform']:
            other_items = list(firmware_json['other_platform']['firmware_versions'].items())[:2]
            for item_name, item_data in other_items:
                status = item_data.get('status', 'MISSING_STATUS')
                version = item_data.get('version', 'MISSING_VERSION')
                print(f"  {item_name}:")
                print(f"    status: {status}")
                print(f"    version: {version}")
    
    conn.close()

if __name__ == "__main__":
    main()