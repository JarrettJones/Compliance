import sqlite3

# Connect to the database
conn = sqlite3.connect('firmware_checker.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Check TestUser's current role
user = cursor.execute("SELECT username, role, is_admin FROM users WHERE username = 'TestUser'").fetchone()
if user:
    print(f"Current TestUser - Role: {user['role']}, is_admin: {user['is_admin']}")
    
    # Update TestUser to viewer
    cursor.execute("UPDATE users SET role = 'viewer' WHERE username = 'TestUser'")
    conn.commit()
    print("Updated TestUser to 'viewer' role")
    
    # Verify the change
    user = cursor.execute("SELECT username, role FROM users WHERE username = 'TestUser'").fetchone()
    print(f"After update - Role: {user['role']}")
else:
    print("TestUser not found")

conn.close()
