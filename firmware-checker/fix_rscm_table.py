#!/usr/bin/env python3
"""
Fix RSCM Firmware Checks Table
Manually adds missing columns to rscm_firmware_checks table
"""

import sqlite3
import sys

print("=" * 80)
print("RSCM FIRMWARE CHECKS TABLE FIX")
print("=" * 80)
print()

# Connect to database
try:
    conn = sqlite3.connect('firmware_checker.db')
    cursor = conn.cursor()
    print("[OK] Connected to database")
except Exception as e:
    print(f"[ERROR] Could not connect to database: {e}")
    sys.exit(1)

print()

# Check current schema
print("Step 1: Checking Current Schema")
print("-" * 80)

try:
    cursor.execute("PRAGMA table_info(rscm_firmware_checks)")
    columns = cursor.fetchall()
    
    print(f"Current columns ({len(columns)}):")
    for col in columns:
        col_id, name, col_type, not_null, default, pk = col
        print(f"  {name} ({col_type})")
    
    existing_cols = [col[1] for col in columns]
    
    missing = []
    if 'rscm_ip' not in existing_cols:
        missing.append('rscm_ip')
    if 'rscm_port' not in existing_cols:
        missing.append('rscm_port')
    if 'position' not in existing_cols:
        missing.append('position')
    
    if not missing:
        print()
        print("[OK] All required columns already exist!")
        conn.close()
        sys.exit(0)
    
    print()
    print(f"Missing columns: {', '.join(missing)}")
    
except Exception as e:
    print(f"[ERROR] Could not check schema: {e}")
    conn.close()
    sys.exit(1)

print()

# Add missing columns
print("Step 2: Adding Missing Columns")
print("-" * 80)

try:
    if 'rscm_ip' in missing:
        print("Adding rscm_ip column...")
        cursor.execute("ALTER TABLE rscm_firmware_checks ADD COLUMN rscm_ip TEXT")
        print("[OK] Added rscm_ip")
    
    if 'rscm_port' in missing:
        print("Adding rscm_port column...")
        cursor.execute("ALTER TABLE rscm_firmware_checks ADD COLUMN rscm_port INTEGER DEFAULT 8080")
        print("[OK] Added rscm_port")
    
    if 'position' in missing:
        print("Adding position column...")
        cursor.execute("ALTER TABLE rscm_firmware_checks ADD COLUMN position TEXT")
        print("[OK] Added position")
    
    conn.commit()
    print()
    print("[OK] All columns added successfully!")
    
except Exception as e:
    print(f"[ERROR] Failed to add columns: {e}")
    conn.rollback()
    conn.close()
    sys.exit(1)

print()

# Verify final schema
print("Step 3: Verifying Final Schema")
print("-" * 80)

try:
    cursor.execute("PRAGMA table_info(rscm_firmware_checks)")
    columns = cursor.fetchall()
    
    print(f"Final columns ({len(columns)}):")
    for col in columns:
        col_id, name, col_type, not_null, default, pk = col
        print(f"  {name} ({col_type})")
    
    existing_cols = [col[1] for col in columns]
    
    has_all = all(c in existing_cols for c in ['rscm_ip', 'rscm_port', 'position'])
    
    print()
    if has_all:
        print("[SUCCESS] All required columns are now present!")
        print()
        print("You can now:")
        print("  1. Restart Flask: python app.py")
        print("  2. Test RSCM firmware checks")
    else:
        print("[WARNING] Some columns are still missing")
    
except Exception as e:
    print(f"[ERROR] Could not verify schema: {e}")

conn.close()

print()
print("=" * 80)
