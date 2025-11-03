#!/usr/bin/env python3
import sqlite3

# Connect to database
conn = sqlite3.connect('firmware_checker.db')
cursor = conn.cursor()

print("Status values in database:")
for row in cursor.execute('SELECT DISTINCT status FROM firmware_checks'):
    print(f' - {row[0]}')

print("\nRecent checks for system 1:")
for row in cursor.execute('SELECT id, status, check_date FROM firmware_checks WHERE system_id = 1 ORDER BY check_date DESC LIMIT 5'):
    print(f'  Check {row[0]}: {row[1]} at {row[2]}')

print("\nAll checks for system 1:")
for row in cursor.execute('SELECT id, status, check_date FROM firmware_checks WHERE system_id = 1 ORDER BY check_date DESC'):
    print(f'  Check {row[0]}: {row[1]} at {row[2]}')

conn.close()