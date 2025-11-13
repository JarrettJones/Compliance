#!/usr/bin/env python3
import sqlite3

# Connect to database
conn = sqlite3.connect('firmware_checker.db')
conn.row_factory = sqlite3.Row

print("Programs:")
programs = conn.execute('SELECT * FROM programs').fetchall()
for p in programs:
    print(f"  ID: {p['id']}, Name: {p['name']}")

print("\nRecipe 1 (before fix):")
recipes = conn.execute('SELECT id, name, program_id FROM firmware_recipes WHERE id=1').fetchall()
for r in recipes:
    print(f"  ID: {r['id']}, Name: {r['name']}, Program ID: {r['program_id']}")

print("\nSystem 5 (from check 70):")
systems = conn.execute('SELECT id, name, program_id FROM systems WHERE id=5').fetchall()
for s in systems:
    print(f"  ID: {s['id']}, Name: {s['name']}, Program ID: {s['program_id']}")

# Fix recipe 1 to be assigned to Echo Falls (program_id=1)
print("\n--- Fixing recipe 1 to be assigned to Echo Falls (program_id=1) ---")
conn.execute('UPDATE firmware_recipes SET program_id = 1 WHERE id = 1')
conn.commit()

print("\nRecipe 1 (after fix):")
recipes = conn.execute('SELECT id, name, program_id FROM firmware_recipes WHERE id=1').fetchall()
for r in recipes:
    print(f"  ID: {r['id']}, Name: {r['name']}, Program ID: {r['program_id']}")

conn.close()
print("\n✅ Recipe fixed! Refresh the check result page to see the 'Compare with Recipe' button.")