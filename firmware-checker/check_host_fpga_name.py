#!/usr/bin/env python3
import sqlite3

conn = sqlite3.connect('firmware_checker.db')
cursor = conn.cursor()

print("=== Host FPGA Firmware Type ===")
cursor.execute("SELECT id, name FROM firmware_types WHERE name LIKE '%Host FPGA%'")
for row in cursor.fetchall():
    print(f"ID: {row[0]}, Name: '{row[1]}'")

conn.close()
