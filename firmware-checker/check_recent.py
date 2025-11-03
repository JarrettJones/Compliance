#!/usr/bin/env python3
import sqlite3
import json

# Connect to database
conn = sqlite3.connect('firmware_checker.db')
cursor = conn.cursor()

print("Most recent check for system 1:")
recent_check = cursor.execute('SELECT * FROM firmware_checks WHERE system_id = 1 ORDER BY check_date DESC LIMIT 1').fetchone()

if recent_check:
    # Convert to dict for easier viewing
    columns = [description[0] for description in cursor.description]
    check_dict = dict(zip(columns, recent_check))
    
    print(f"ID: {check_dict['id']}")
    print(f"System ID: {check_dict['system_id']}")
    print(f"Status: {check_dict['status']}")
    print(f"Check Date: {check_dict['check_date']}")
    print(f"Error Message: {check_dict['error_message']}")
    print(f"Firmware Data Length: {len(check_dict['firmware_data']) if check_dict['firmware_data'] else 0}")
    
    # Try to parse firmware data
    if check_dict['firmware_data'] and check_dict['firmware_data'] != '{}':
        try:
            firmware_data = json.loads(check_dict['firmware_data'])
            print(f"Firmware Data Keys: {list(firmware_data.keys())}")
            print(f"Has dc_scm: {'dc_scm' in firmware_data}")
            print(f"Has ovl2: {'ovl2' in firmware_data}")
            print(f"Has other_platform: {'other_platform' in firmware_data}")
        except json.JSONDecodeError as e:
            print(f"JSON Decode Error: {e}")
            print(f"Raw firmware_data (first 200 chars): {check_dict['firmware_data'][:200]}")
    else:
        print("No firmware data or empty data")
else:
    print("No recent check found")

conn.close()