#!/usr/bin/env python3
"""
One-time script to fix recipes on production server.
This assigns all recipes with NULL program_id to Echo Falls (program_id=1).
"""
import sqlite3

# Connect to database
conn = sqlite3.connect('firmware_checker.db')
conn.row_factory = sqlite3.Row

print("Recipes before fix:")
recipes = conn.execute('SELECT id, name, program_id FROM firmware_recipes').fetchall()
for r in recipes:
    print(f"  ID: {r['id']}, Name: {r['name']}, Program ID: {r['program_id']}")

# Update all recipes with NULL program_id to Echo Falls (program_id=1)
print("\n--- Updating recipes to Echo Falls (program_id=1) ---")
result = conn.execute('UPDATE firmware_recipes SET program_id = 1 WHERE program_id IS NULL')
rows_updated = result.rowcount
conn.commit()

print(f"Updated {rows_updated} recipe(s)")

print("\nRecipes after fix:")
recipes = conn.execute('SELECT id, name, program_id FROM firmware_recipes').fetchall()
for r in recipes:
    print(f"  ID: {r['id']}, Name: {r['name']}, Program ID: {r['program_id']}")

conn.close()
print("\n✅ Done! All recipes now assigned to Echo Falls.")
