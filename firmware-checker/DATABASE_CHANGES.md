# Database Schema Changes Summary

## Overview
This document summarizes ALL database schema changes made during the feature/improvements branch development. These changes will be automatically applied when you start the Flask application on production.

---

## How Migrations Work

The `init_db()` function in `app.py` handles all migrations automatically:
1. **Creates new tables** with `CREATE TABLE IF NOT EXISTS`
2. **Adds missing columns** by checking `PRAGMA table_info` and running `ALTER TABLE ADD COLUMN`
3. **Migrates existing data** from old structure to new structure
4. **Safe to run multiple times** - won't duplicate or break existing data

---

## Complete List of Changes

### 1. NEW TABLES (Location Normalization)

#### `locations` table
```sql
CREATE TABLE locations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,          -- e.g., "Quincy", "Des Moines"
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```

#### `buildings` table
```sql
CREATE TABLE buildings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    location_id INTEGER NOT NULL,        -- Links to locations.id
    name TEXT NOT NULL,                  -- e.g., "DF1", "QCY1"
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(location_id, name),
    FOREIGN KEY (location_id) REFERENCES locations (id) ON DELETE CASCADE
)
```

#### `rooms` table
```sql
CREATE TABLE rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    building_id INTEGER NOT NULL,        -- Links to buildings.id
    name TEXT NOT NULL,                  -- e.g., "Room 101", "Lab 5"
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(building_id, name),
    FOREIGN KEY (building_id) REFERENCES buildings (id) ON DELETE CASCADE
)
```

**Migration**: Old `racks.location` and `racks.room` columns are automatically parsed and migrated to the normalized structure.

---

### 2. NEW TABLE (RSCM Firmware Checks)

#### `rscm_firmware_checks` table ⚠️ CRITICAL
```sql
CREATE TABLE rscm_firmware_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rack_id INTEGER NOT NULL,
    rscm_ip TEXT,                        -- ADDED: IP address used for check
    rscm_port INTEGER DEFAULT 8080,      -- ADDED: Port used for check
    position TEXT,                       -- ADDED: 'upper' or 'lower'
    check_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    firmware_data TEXT NOT NULL,         -- JSON firmware data
    status TEXT NOT NULL DEFAULT 'success',
    error_message TEXT,
    user_id INTEGER,
    FOREIGN KEY (rack_id) REFERENCES racks (id),
    FOREIGN KEY (user_id) REFERENCES users (id)
)
```

**Why Critical**: The INSERT statement at line 4947 requires `rscm_ip`, `rscm_port`, and `position`. Without these columns, RSCM firmware checks will crash.

**Added in**: Commit ad5d26b (most recent fix)

---

### 3. MODIFIED TABLES

#### `racks` table - Added RSCM IP columns
```sql
ALTER TABLE racks ADD COLUMN rscm_upper_ip TEXT;      -- IP for upper RSCM
ALTER TABLE racks ADD COLUMN rscm_lower_ip TEXT;      -- IP for lower RSCM
ALTER TABLE racks ADD COLUMN rscm_ip TEXT;            -- IP for benches (single RSCM)
ALTER TABLE racks ADD COLUMN room_id INTEGER;         -- Link to rooms table
```

**Migration**: If `rscm_components` table exists, IPs are automatically migrated from there.

#### `users` table - Role-based access control
```sql
ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'viewer';           -- 'admin', 'editor', 'viewer'
ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1;          -- Account enabled/disabled
ALTER TABLE users ADD COLUMN email TEXT;                           -- User email
ALTER TABLE users ADD COLUMN first_name TEXT;                      -- First name
ALTER TABLE users ADD COLUMN last_name TEXT;                       -- Last name
ALTER TABLE users ADD COLUMN team TEXT;                            -- Team/department
ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0; -- Force password change
```

**Migration**: Old `is_admin` column is automatically converted to `role` ('admin' or 'editor').

#### `systems` table - Program association
```sql
ALTER TABLE systems ADD COLUMN program_id INTEGER;     -- Link to programs.id
ALTER TABLE systems ADD COLUMN created_by INTEGER;     -- User who created system
```

**Migration**: All existing systems are assigned to "Echo Falls" program (auto-created).

#### `firmware_checks` table - Tracking
```sql
ALTER TABLE firmware_checks ADD COLUMN user_id INTEGER;    -- Who ran the check
ALTER TABLE firmware_checks ADD COLUMN recipe_id INTEGER;  -- Which recipe was used
```

#### `firmware_recipes` table - Program association
```sql
ALTER TABLE firmware_recipes ADD COLUMN program_id INTEGER; -- Link to programs.id
```

**Migration**: All existing recipes are assigned to "Echo Falls" program.

#### `access_requests` table - Self-service account creation
```sql
ALTER TABLE access_requests ADD COLUMN username TEXT;          -- Requested username
ALTER TABLE access_requests ADD COLUMN password_hash TEXT;     -- Pre-hashed password
```

---

## Migration Summary by Category

### Data Normalization
- ✅ Locations → Buildings → Rooms → Racks hierarchy
- ✅ Automatic migration from old `location` and `room` text fields
- ✅ Maintains data integrity with foreign keys and cascading deletes

### RSCM Management
- ✅ RSCM IP addresses stored on racks (upper/lower/single)
- ✅ RSCM firmware checks with position tracking
- ✅ Supports both rack-level and system-level checks

### User Management
- ✅ Role-based access control (admin/editor/viewer)
- ✅ User profiles with email, name, team
- ✅ Self-service access requests with approval workflow
- ✅ Force password change on first login

### Program Management
- ✅ Multiple programs support (Echo Falls, etc.)
- ✅ Program-specific firmware types
- ✅ Program-specific custom fields
- ✅ Systems and recipes linked to programs

### Audit Trail
- ✅ Track who created systems
- ✅ Track who ran firmware checks
- ✅ Track which recipe was used
- ✅ Timestamps on all major tables

---

## Tables and Column Counts

| Table | Total Columns | New Columns |
|-------|--------------|-------------|
| programs | 7 | 7 (new table) |
| locations | 4 | 4 (new table) |
| buildings | 5 | 5 (new table) |
| rooms | 5 | 5 (new table) |
| racks | 11 | 4 (rscm IPs + room_id) |
| systems | 10 | 2 (program_id, created_by) |
| firmware_checks | 8 | 2 (user_id, recipe_id) |
| rscm_firmware_checks | 10 | 10 (new table) |
| firmware_types | 4 | 4 (new table) |
| program_firmware_types | 2 | 2 (new table) |
| program_custom_fields | 10 | 10 (new table) |
| system_custom_field_values | 6 | 6 (new table) |
| firmware_recipes | 7 | 1 (program_id) |
| users | 11 | 7 (role, email, names, etc.) |
| access_requests | 10 | 2 (username, password_hash) |

**Total**: 15 tables, ~110 columns

---

## Critical Columns for Production

### Must exist for RSCM checks to work:
- ✅ `rscm_firmware_checks.rscm_ip`
- ✅ `rscm_firmware_checks.rscm_port`
- ✅ `rscm_firmware_checks.position`

### Must exist for location management:
- ✅ `locations.id`, `locations.name`
- ✅ `buildings.id`, `buildings.location_id`
- ✅ `rooms.id`, `rooms.building_id`
- ✅ `racks.room_id`

### Must exist for user management:
- ✅ `users.role`
- ✅ `users.is_active`
- ✅ `users.email`

### Must exist for program management:
- ✅ `programs.id`, `programs.name`, `programs.check_methodology`
- ✅ `systems.program_id`
- ✅ `firmware_recipes.program_id`

---

## Verification Command

Run this to verify all changes are applied:
```powershell
python .\verify_database_migration.ps1
```

Expected output:
```
[OK] All required tables and columns exist!

Database Schema Summary:
--------------------------------------------------------------------------------
  access_requests (10 columns)
  buildings (5 columns)
  firmware_checks (8 columns)
  firmware_recipes (7 columns)
  firmware_types (4 columns)
  locations (4 columns)
  program_custom_fields (10 columns)
  program_firmware_types (2 columns)
  programs (7 columns)
  racks (11 columns)
  rooms (5 columns)
  rscm_firmware_checks (10 columns)
  system_custom_field_values (6 columns)
  systems (10 columns)
  users (11 columns)
```

---

## What Happens on Production Startup

1. **Flask starts** → Calls `init_db()`
2. **Check tables** → Creates any missing tables with `CREATE TABLE IF NOT EXISTS`
3. **Check columns** → Runs `PRAGMA table_info` on each table
4. **Add columns** → Runs `ALTER TABLE ADD COLUMN` for missing columns
5. **Migrate data** → Moves data from old structure to new (if needed)
6. **Create defaults** → Creates "Echo Falls" program if it doesn't exist
7. **Ready** → Application starts serving requests

**Expected Log Messages**:
```
INFO:app:Added rscm_ip column to rscm_firmware_checks table
INFO:app:Added rscm_port column to rscm_firmware_checks table
INFO:app:Added position column to rscm_firmware_checks table
INFO:app:Added role column to users table
INFO:app:Added email column to users table
INFO:app:Migrated is_admin to role column
INFO:app:Added program_id column to systems table
INFO:app:Migrated existing systems to Echo Falls program
```

---

## Rollback Procedure

If something goes wrong:

### Option 1: Restore from backup
```powershell
# Stop Flask (Ctrl+C)
Copy-Item firmware_checker.db.backup-TIMESTAMP firmware_checker.db -Force
python app.py
```

### Option 2: Fresh start (loses data)
```powershell
# Stop Flask (Ctrl+C)
Remove-Item firmware_checker.db
python app.py  # Creates fresh database with latest schema
```

### Option 3: Manual SQL fixes
```powershell
# Connect to database
sqlite3 firmware_checker.db

# Check specific table
.schema rscm_firmware_checks

# Add missing column manually
ALTER TABLE rscm_firmware_checks ADD COLUMN rscm_ip TEXT;
ALTER TABLE rscm_firmware_checks ADD COLUMN rscm_port INTEGER DEFAULT 8080;
ALTER TABLE rscm_firmware_checks ADD COLUMN position TEXT;

# Exit
.exit

# Restart Flask
python app.py
```

---

## Testing After Migration

1. ✅ Log in to application
2. ✅ Navigate to Locations → should see cities
3. ✅ Navigate to Buildings → should see buildings
4. ✅ Navigate to Rooms → should see rooms
5. ✅ Navigate to Racks → should see RSCM IPs
6. ✅ Click rack → "Check RSCM Firmware" → should work without errors
7. ✅ Navigate to Systems → should see program names
8. ✅ Run system firmware check → should work
9. ✅ Check user management → should see roles (admin/editor/viewer)
10. ✅ Test access request → should allow username/password setup

---

## Support

If migration fails or shows errors:
1. Check Flask terminal for error messages
2. Run `python .\verify_database_migration.ps1`
3. Check specific table: `sqlite3 firmware_checker.db ".schema TABLE_NAME"`
4. Check logs for "Migration warning" messages (usually safe to ignore)
5. If needed, restore from backup and try again

**Most Common Issue**: "table X has no column named Y"
**Solution**: Stop Flask, delete database (or restore backup), restart Flask

---

## File Locations

- **app.py**: Lines 104-600 contain all migration logic
- **verify_database_migration.ps1**: Verification script
- **PRODUCTION_DEPLOYMENT_CHECKLIST.md**: Full deployment guide
- **firmware_checker.db**: SQLite database file (auto-created)

---

## Commit History

- `ad5d26b` - Add missing columns to rscm_firmware_checks table (rscm_ip, rscm_port, position)
- `c8b6e85` - Update nginx setup script to use correct SSL certificate paths
- `abc51f4` - Add database migration verification script and deployment checklist

**Current Branch**: feature/improvements  
**Ready for Production**: ✅ Yes
