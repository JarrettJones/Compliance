# Production Deployment Checklist

## Current State
- **Branch**: feature/improvements
- **Latest Commit**: ad5d26b - "Add missing columns to rscm_firmware_checks table"
- **Production Server**: dca20301103n414.redmond.corp.microsoft.com

---

## Critical Database Changes

### 1. Location/Building/Room Normalization
**New Tables**:
- `locations` - Cities (e.g., Quincy, Des Moines)
- `buildings` - Buildings within locations
- `rooms` - Rooms within buildings
- `racks.room_id` - Foreign key to rooms table

**Migration**: Automatic - old `location` and `room` columns migrated to normalized structure

### 2. RSCM Firmware Checks (Most Recent Fix)
**New Table**: `rscm_firmware_checks`
```sql
CREATE TABLE rscm_firmware_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rack_id INTEGER NOT NULL,
    rscm_ip TEXT,                    -- ⚠️ Added in commit ad5d26b
    rscm_port INTEGER DEFAULT 8080,  -- ⚠️ Added in commit ad5d26b
    position TEXT,                   -- ⚠️ Added in commit ad5d26b
    check_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    firmware_data TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'success',
    error_message TEXT,
    user_id INTEGER,
    FOREIGN KEY (rack_id) REFERENCES racks (id),
    FOREIGN KEY (user_id) REFERENCES users (id)
)
```

**Why This Matters**: The INSERT statement at line 4947 requires these columns. Without them, RSCM firmware checks will fail with error:
```
table rscm_firmware_checks has no column named rscm_ip
```

### 3. RSCM IP Columns on Racks
**New Columns**:
- `racks.rscm_upper_ip` - IP for upper RSCM
- `racks.rscm_lower_ip` - IP for lower RSCM
- `racks.rscm_ip` - IP for benches (single RSCM)

**Migration**: Automatic - migrates data from old `rscm_components` table if it exists

### 4. User Management Enhancements
**New Columns**:
- `users.role` - 'admin', 'editor', or 'viewer' (replaces is_admin)
- `users.email`
- `users.first_name`
- `users.last_name`
- `users.team`
- `users.must_change_password`
- `users.is_active`

**Access Requests**:
- `access_requests.username`
- `access_requests.password_hash`

**Migration**: Automatic - migrates `is_admin` to `role` column

### 5. Program Association
**New Columns**:
- `systems.program_id` - Link system to program (e.g., Echo Falls)
- `firmware_recipes.program_id` - Link recipe to program

**Migration**: Automatic - creates "Echo Falls" program and assigns existing systems/recipes to it

### 6. Tracking Fields
**New Columns**:
- `firmware_checks.user_id` - Track who ran the check
- `firmware_checks.recipe_id` - Track which recipe was used
- `systems.created_by` - Track who created the system

---

## Deployment Steps

### Step 1: Backup Current Database ✅
```powershell
cd C:\Users\jarrettjones\Compliance\firmware-checker
Copy-Item firmware_checker.db firmware_checker.db.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')
```

### Step 2: Stop Flask Application ✅
```powershell
# In the terminal running Flask, press Ctrl+C
```

### Step 3: Pull Latest Changes ✅
```powershell
git fetch origin
git checkout feature/improvements
git pull origin feature/improvements
```

**Expected Output**:
```
From https://github.com/JarrettJones/Compliance
 * branch            feature/improvements -> FETCH_HEAD
Updating c8b6e85..ad5d26b
Fast-forward
 app.py | 3 +++
 1 file changed, 3 insertions(+)
```

### Step 4: Verify Database Migration ✅
```powershell
python .\verify_database_migration.ps1
```

**Expected Output**: Should show all tables and columns exist

### Step 5: Start Flask Application ✅
```powershell
python app.py
```

**What Happens**: 
- `init_db()` function automatically runs
- Creates any missing tables
- Adds any missing columns
- Migrates old data to new structure
- Creates default "Echo Falls" program if needed

**Watch For**:
```
INFO:app:Added rscm_ip column to rscm_firmware_checks table
INFO:app:Added rscm_port column to rscm_firmware_checks table
INFO:app:Added position column to rscm_firmware_checks table
```

### Step 6: Verify Application Access ✅
Open browser to: `https://dca20301103n414/firmware-checker/`

**Expected**:
- ✅ Site loads without errors
- ✅ SSL shows as secure
- ✅ Can log in
- ✅ Can view racks/systems
- ✅ Can run firmware checks
- ⚠️ **Test RSCM firmware check specifically** - this was the last fix

---

## Testing Checklist

### Critical Tests
- [ ] Log in to application
- [ ] View locations/buildings/rooms (normalized structure)
- [ ] View racks with RSCM IPs
- [ ] View systems
- [ ] **Run RSCM firmware check** ⚠️ Most important!
- [ ] Run regular system firmware check
- [ ] Create new user via access request
- [ ] Verify user roles (admin/editor/viewer)

### RSCM Firmware Check Test
1. Navigate to rack with RSCM IP configured
2. Click "Check RSCM Firmware"
3. Should see firmware check start without errors
4. Check should complete and store results

**If you get error**: "table rscm_firmware_checks has no column named rscm_ip"
→ Database migration didn't run properly. Stop Flask, delete database, restart Flask.

---

## Rollback Procedure (If Needed)

### If Application Won't Start:
```powershell
# Stop Flask (Ctrl+C)

# Restore database backup
Copy-Item firmware_checker.db.backup-YYYYMMDD-HHMMSS firmware_checker.db -Force

# Go back to previous commit
git checkout c8b6e85

# Restart Flask
python app.py
```

### If Database Is Corrupted:
```powershell
# Stop Flask (Ctrl+C)

# Delete database (will lose data)
Remove-Item firmware_checker.db

# Restart Flask (creates fresh database)
python app.py
```

---

## Files Changed in This Deployment

### Main Application
- **app.py** (commit ad5d26b)
  - Lines 210-223: Added rscm_ip, rscm_port, position columns to rscm_firmware_checks table
  - Lines 123-175: Location/building/room normalized tables
  - Lines 330-600: Comprehensive migration logic

### SSL/nginx Configuration
- **fix_ssl_certificate_chain.ps1** (commit c8b6e85)
  - Exports organization certificate with full chain
  - Excludes self-signed certificates
  - Updates nginx configuration

- **setup_nginx_proxy.ps1** (commit c8b6e85)
  - Uses server-fullchain.crt (includes intermediate CA)
  - Uses server-new.key
  - Validates configuration before applying

### Verification Tools
- **verify_database_migration.ps1** (new)
  - Checks all required tables exist
  - Verifies all required columns present
  - Highlights missing migrations

---

## Known Issues & Resolutions

### Issue 1: "table rscm_firmware_checks has no column named rscm_ip"
**Cause**: Database didn't get latest schema updates
**Resolution**: Stop Flask, delete `firmware_checker.db`, restart Flask
**Status**: Fixed in commit ad5d26b

### Issue 2: SSL Certificate Not Secure
**Cause**: Missing intermediate CA in certificate chain
**Resolution**: Run `.\fix_ssl_certificate_chain.ps1` to export full chain
**Status**: Fixed in commit c8b6e85

### Issue 3: nginx Loading Wrong Configuration
**Cause**: nginx restart restored old backup config (JollyGrid/sureshvakati)
**Resolution**: Run `.\setup_nginx_proxy.ps1` to apply correct config
**Status**: Fixed in commit c8b6e85

---

## Post-Deployment Monitoring

### Check Flask Logs
```powershell
# Flask runs in terminal, watch for:
# - No errors on startup
# - "Running on http://127.0.0.1:5000" message
# - Migration log messages (INFO:app:Added ... column)
```

### Check nginx Logs
```powershell
cd C:\nginx\logs
Get-Content .\error.log -Tail 20
Get-Content .\access.log -Tail 20
```

### Check Database Size
```powershell
Get-Item .\firmware_checker.db | Select-Object Name, Length, LastWriteTime
```

### Verify SSL Certificate
```powershell
# In browser, click lock icon → Certificate → Details
# Should show:
# - Issued to: DCA20301103N414.redmond.corp.microsoft.com
# - Issued by: MSIT CA Z2
# - Valid until: November 12, 2026
# - Certificate chain: 2 certificates (server + intermediate CA)
```

---

## Success Criteria

✅ All checkpoints must pass:
1. Flask application starts without errors
2. Database migration completes (check logs for "Added ... column" messages)
3. Site accessible at https://dca20301103n414/firmware-checker/
4. SSL shows as secure (green lock icon)
5. Can log in successfully
6. Can view locations/buildings/rooms/racks/systems
7. **Can run RSCM firmware check without errors** ⚠️
8. Can run regular system firmware check
9. No errors in Flask terminal output
10. No errors in nginx error.log

---

## Contact & Support

If deployment fails:
1. Check Flask terminal output for error messages
2. Run `.\verify_database_migration.ps1` to check database state
3. Check nginx logs at `C:\nginx\logs\error.log`
4. Restore from backup if needed (see Rollback Procedure)

---

## Deployment History

- **2024-12-04**: Initial deployment to production
  - Branch: feature/improvements
  - Commit: ad5d26b
  - Key Changes: Database normalization, RSCM firmware checks, user management
  - Status: Ready for deployment
