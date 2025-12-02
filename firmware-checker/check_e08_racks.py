import sqlite3

conn = sqlite3.connect('firmware_checker.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("E08 Racks in Database:")
print("=" * 80)

rows = cursor.execute("""
    SELECT id, name, location, room, 
           (SELECT COUNT(*) FROM systems WHERE rack_id = racks.id) as system_count
    FROM racks 
    WHERE name LIKE '%E08%' 
    ORDER BY name
""").fetchall()

for row in rows:
    print(f"ID: {row['id']}")
    print(f"  Name: {row['name']}")
    print(f"  Location: {row['location']}")
    print(f"  Room: {row['room']}")
    print(f"  Systems: {row['system_count']}")
    print()

print(f"\nTotal E08 racks found: {len(rows)}")

# Show systems in E08 Bench
print("\n" + "=" * 80)
print("Systems in E08 Bench:")
print("=" * 80)
systems = cursor.execute("""
    SELECT s.id, s.name, s.rack_id, r.name as rack_name
    FROM systems s
    JOIN racks r ON s.rack_id = r.id
    WHERE r.name LIKE '%E08%'
    ORDER BY r.name, s.name
""").fetchall()

for sys in systems:
    print(f"System: {sys['name']} (ID: {sys['id']}) -> Rack: {sys['rack_name']} (ID: {sys['rack_id']})")

conn.close()
