#!/usr/bin/env python3

import sqlite3
from datetime import datetime, timedelta

def check_running_status():
    conn = sqlite3.connect('firmware_checker.db')
    cursor = conn.cursor()
    
    # Check specific ID 53
    cursor.execute('SELECT id, system_id, check_date, status FROM firmware_checks WHERE id = 53')
    result = cursor.fetchone()
    if result:
        print(f'Check 53: ID={result[0]}, System={result[1]}, Date={result[2]}, Status={result[3]}')
    else:
        print('Check 53: Not found')
    
    # Check all running checks
    cursor.execute('SELECT id, system_id, check_date, status FROM firmware_checks WHERE status = "running"')
    running = cursor.fetchall()
    print(f'\nRunning checks ({len(running)}):')
    
    for r in running:
        # Parse check date to see how long it's been running
        check_date = datetime.fromisoformat(r[2].replace('Z', '+00:00') if 'Z' in r[2] else r[2])
        now = datetime.now()
        duration = now - check_date
        print(f'  ID={r[0]}, System={r[1]}, Started={r[2]}, Duration={duration}')
    
    conn.close()
    
    return running

if __name__ == "__main__":
    check_running_status()