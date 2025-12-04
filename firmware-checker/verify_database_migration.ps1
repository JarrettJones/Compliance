# Database Migration Verification Script
# This script verifies all database changes are applied correctly on production

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Database Migration Verification Script" -ForegroundColor Yellow
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

# Configuration
$dbPath = ".\firmware_checker.db"

if (-not (Test-Path $dbPath)) {
    Write-Host "[ERROR] Database not found at: $dbPath" -ForegroundColor Red
    Write-Host "Current directory: $(Get-Location)" -ForegroundColor Yellow
    exit 1
}

Write-Host "[OK] Found database at: $dbPath" -ForegroundColor Green
Write-Host ""

# Required tables with their key columns
$requiredTables = @{
    'programs' = @('id', 'name', 'description', 'check_methodology', 'is_active')
    'locations' = @('id', 'name', 'description')
    'buildings' = @('id', 'location_id', 'name')
    'rooms' = @('id', 'building_id', 'name')
    'racks' = @('id', 'name', 'room_id', 'rack_type', 'rscm_upper_ip', 'rscm_lower_ip', 'rscm_ip')
    'systems' = @('id', 'name', 'rscm_ip', 'rscm_port', 'program_id', 'created_by')
    'firmware_checks' = @('id', 'system_id', 'check_date', 'firmware_data', 'status', 'user_id', 'recipe_id')
    'rscm_firmware_checks' = @('id', 'rack_id', 'rscm_ip', 'rscm_port', 'position', 'check_date', 'firmware_data', 'status', 'user_id')
    'firmware_types' = @('id', 'category', 'name', 'description')
    'program_firmware_types' = @('program_id', 'firmware_type_id')
    'program_custom_fields' = @('id', 'program_id', 'field_name', 'field_label', 'field_type', 'is_required')
    'system_custom_field_values' = @('id', 'system_id', 'field_id', 'field_value')
    'firmware_recipes' = @('id', 'name', 'description', 'firmware_versions', 'program_id')
    'users' = @('id', 'username', 'password_hash', 'role', 'is_active', 'email', 'first_name', 'last_name', 'team', 'must_change_password')
    'access_requests' = @('id', 'email', 'first_name', 'business_justification', 'status', 'username', 'password_hash')
}

# Load SQLite assembly
Add-Type -Path "System.Data.SQLite.dll" -ErrorAction SilentlyContinue

# Function to get SQLite connection
function Get-SQLiteConnection {
    param([string]$DatabasePath)
    
    try {
        # Try using sqlite3.exe if available
        $sqlite3Paths = @(
            "sqlite3.exe",
            "C:\Program Files\Git\usr\bin\sqlite3.exe",
            "C:\sqlite\sqlite3.exe"
        )
        
        foreach ($path in $sqlite3Paths) {
            $resolved = $null
            if ($path -eq "sqlite3.exe") {
                $resolved = (Get-Command sqlite3 -ErrorAction SilentlyContinue)
                if ($resolved) {
                    return $resolved.Source
                }
            } elseif (Test-Path $path) {
                return $path
            }
        }
        
        return $null
    } catch {
        return $null
    }
}

# Get SQLite executable
$sqlite3 = Get-SQLiteConnection

if (-not $sqlite3) {
    Write-Host "[WARNING] sqlite3.exe not found - will check using Python instead" -ForegroundColor Yellow
    Write-Host ""
    
    # Use Python to verify database
    Write-Host "Checking database using Python..." -ForegroundColor Cyan
    
    # Create Python script content
    $requiredTablesJson = $requiredTables | ConvertTo-Json -Compress
    $dbPathEscaped = $dbPath.Replace('\', '/')
    
    $pythonScript = @"
import sqlite3
import json
import sys

db_path = '$dbPathEscaped'
required_tables = json.loads('$requiredTablesJson')

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    
    results = {
        'success': True,
        'tables': {},
        'missing_tables': [],
        'missing_columns': {}
    }
    
    for table, columns in required_tables.items():
        if table not in tables:
            results['missing_tables'].append(table)
            results['success'] = False
            continue
            
        # Get table columns
        cursor.execute("PRAGMA table_info({})".format(table))
        existing_columns = [row[1] for row in cursor.fetchall()]
        results['tables'][table] = existing_columns
        
        # Check for missing columns
        missing = [col for col in columns if col not in existing_columns]
        if missing:
            results['missing_columns'][table] = missing
            results['success'] = False
    
    print(json.dumps(results, indent=2))
    conn.close()
    
except Exception as e:
    result = {'success': False, 'error': str(e)}
    print(json.dumps(result), file=sys.stderr)
    sys.exit(1)
"@
    
    $tempScript = [System.IO.Path]::GetTempFileName() + ".py"
    $pythonScript | Out-File -FilePath $tempScript -Encoding UTF8
    
    try {
        $output = python $tempScript 2>&1
        
        # Check if output is valid JSON
        if ($output -match '^\s*\{') {
            $result = $output | ConvertFrom-Json
        } else {
            Write-Host "[ERROR] Python script failed:" -ForegroundColor Red
            Write-Host $output -ForegroundColor Yellow
            Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
            exit 1
        }
        
        Remove-Item $tempScript -Force
        
        if ($result.success) {
            Write-Host "[OK] All required tables and columns exist!" -ForegroundColor Green
            Write-Host ""
            
            Write-Host "Database Schema Summary:" -ForegroundColor Yellow
            Write-Host ("-" * 80)
            
            # Convert tables to PSCustomObject for proper iteration
            $tableNames = $result.tables.PSObject.Properties.Name | Sort-Object
            foreach ($table in $tableNames) {
                $columnCount = $result.tables.$table.Count
                Write-Host "  $table" -ForegroundColor White -NoNewline
                Write-Host " ($columnCount columns)" -ForegroundColor Gray
            }
            Write-Host ""
            
        } else {
            Write-Host "[ERROR] Database migration incomplete!" -ForegroundColor Red
            Write-Host ""
            
            if ($result.missing_tables.Count -gt 0) {
                Write-Host "Missing Tables:" -ForegroundColor Red
                foreach ($table in $result.missing_tables) {
                    Write-Host "  - $table" -ForegroundColor Yellow
                }
                Write-Host ""
            }
            
            if ($result.missing_columns.Count -gt 0) {
                Write-Host "Missing Columns:" -ForegroundColor Red
                $missingTableNames = $result.missing_columns.PSObject.Properties.Name
                foreach ($table in $missingTableNames) {
                    Write-Host "  Table: $table" -ForegroundColor Yellow
                    foreach ($col in $result.missing_columns.$table) {
                        Write-Host "    - $col" -ForegroundColor Gray
                    }
                }
                Write-Host ""
            }
            
            Write-Host "ACTION REQUIRED:" -ForegroundColor Yellow
            Write-Host "  1. Stop the Flask application (Ctrl+C)" -ForegroundColor White
            Write-Host "  2. Run: python app.py" -ForegroundColor White
            Write-Host "  The init_db() function will automatically create missing tables/columns" -ForegroundColor White
            Write-Host ""
            
            exit 1
        }
        
    } catch {
        Write-Host "[ERROR] Failed to verify database: $($_.Exception.Message)" -ForegroundColor Red
        Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
        exit 1
    }
    
} else {
    Write-Host "[OK] Found sqlite3 at: $sqlite3" -ForegroundColor Green
    Write-Host ""
    
    # Verify each table and its columns
    Write-Host "Verifying Database Schema..." -ForegroundColor Cyan
    Write-Host "-" * 80
    
    $allGood = $true
    $missingTables = @()
    $missingColumns = @{}
    
    foreach ($table in $requiredTables.Keys | Sort-Object) {
        $requiredColumns = $requiredTables[$table]
        
        # Check if table exists
        $tableCheck = & $sqlite3 $dbPath "SELECT name FROM sqlite_master WHERE type='table' AND name='$table';" 2>&1
        
        if ([string]::IsNullOrEmpty($tableCheck)) {
            Write-Host "[MISSING] Table: $table" -ForegroundColor Red
            $missingTables += $table
            $allGood = $false
            continue
        }
        
        # Get existing columns
        $existingColumns = & $sqlite3 $dbPath "PRAGMA table_info($table);" 2>&1 | 
            ForEach-Object { ($_ -split '\|')[1] }
        
        # Check for missing columns
        $missing = $requiredColumns | Where-Object { $_ -notin $existingColumns }
        
        if ($missing.Count -gt 0) {
            Write-Host "[INCOMPLETE] Table: $table" -ForegroundColor Yellow
            Write-Host "  Missing columns: $($missing -join ', ')" -ForegroundColor Gray
            $missingColumns[$table] = $missing
            $allGood = $false
        } else {
            Write-Host "[OK] Table: $table ($($existingColumns.Count) columns)" -ForegroundColor Green
        }
    }
    
    Write-Host ""
    
    if ($allGood) {
        Write-Host "=" * 80 -ForegroundColor Green
        Write-Host "[SUCCESS] All database migrations are complete!" -ForegroundColor Green
        Write-Host "=" * 80 -ForegroundColor Green
        Write-Host ""
        Write-Host "Database is ready for production use." -ForegroundColor White
        Write-Host ""
        
    } else {
        Write-Host "=" * 80 -ForegroundColor Red
        Write-Host "[ERROR] Database migration incomplete!" -ForegroundColor Red
        Write-Host "=" * 80 -ForegroundColor Red
        Write-Host ""
        
        if ($missingTables.Count -gt 0) {
            Write-Host "Missing Tables:" -ForegroundColor Yellow
            foreach ($table in $missingTables) {
                Write-Host "  - $table" -ForegroundColor White
            }
            Write-Host ""
        }
        
        if ($missingColumns.Keys.Count -gt 0) {
            Write-Host "Incomplete Tables (missing columns):" -ForegroundColor Yellow
            foreach ($table in $missingColumns.Keys) {
                Write-Host "  Table: $table" -ForegroundColor White
                foreach ($col in $missingColumns[$table]) {
                    Write-Host "    - $col" -ForegroundColor Gray
                }
            }
            Write-Host ""
        }
        
        Write-Host "ACTION REQUIRED:" -ForegroundColor Yellow
        Write-Host "  1. Stop the Flask application (Ctrl+C)" -ForegroundColor White
        Write-Host "  2. Run: python app.py" -ForegroundColor White
        Write-Host "  The init_db() function will automatically create missing tables/columns" -ForegroundColor White
        Write-Host ""
        
        exit 1
    }
}

# Additional checks
Write-Host "Additional Verification:" -ForegroundColor Cyan
Write-Host "-" * 80

# Check for rscm_firmware_checks specific columns (most recent fix)
$checkScript = @"
import sqlite3
conn = sqlite3.connect('$($dbPath.Replace('\', '\\'))')
cursor = conn.cursor()
cursor.execute("PRAGMA table_info(rscm_firmware_checks)")
columns = [row[1] for row in cursor.fetchall()]
required = ['rscm_ip', 'rscm_port', 'position']
missing = [col for col in required if col not in columns]
if missing:
    print('MISSING:' + ','.join(missing))
else:
    print('OK')
conn.close()
"@

$tempCheck = [System.IO.Path]::GetTempFileName() + ".py"
$checkScript | Out-File -FilePath $tempCheck -Encoding UTF8
$rscmCheck = python $tempCheck 2>&1
Remove-Item $tempCheck -Force

if ($rscmCheck -like "OK") {
    Write-Host "[OK] rscm_firmware_checks has all required columns (rscm_ip, rscm_port, position)" -ForegroundColor Green
} elseif ($rscmCheck -like "MISSING:*") {
    $missing = $rscmCheck -replace "MISSING:", ""
    Write-Host "[ERROR] rscm_firmware_checks missing columns: $missing" -ForegroundColor Red
    Write-Host "  This will cause runtime errors when checking RSCM firmware!" -ForegroundColor Yellow
} else {
    Write-Host "[WARNING] Could not verify rscm_firmware_checks columns" -ForegroundColor Yellow
}

Write-Host ""

# Summary
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Migration Summary" -ForegroundColor Yellow
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""
Write-Host "Key Changes Included in This Migration:" -ForegroundColor White
Write-Host "  1. Location/Building/Room Normalization" -ForegroundColor Gray
Write-Host "     - locations table (cities)" -ForegroundColor Gray
Write-Host "     - buildings table (buildings in locations)" -ForegroundColor Gray
Write-Host "     - rooms table (rooms in buildings)" -ForegroundColor Gray
Write-Host "     - racks.room_id foreign key" -ForegroundColor Gray
Write-Host ""
Write-Host "  2. RSCM IP Columns on Racks" -ForegroundColor Gray
Write-Host "     - racks.rscm_upper_ip" -ForegroundColor Gray
Write-Host "     - racks.rscm_lower_ip" -ForegroundColor Gray
Write-Host "     - racks.rscm_ip (for benches)" -ForegroundColor Gray
Write-Host ""
Write-Host "  3. RSCM Firmware Checks Table" -ForegroundColor Gray
Write-Host "     - rscm_firmware_checks.rack_id" -ForegroundColor Gray
Write-Host "     - rscm_firmware_checks.rscm_ip" -ForegroundColor Gray
Write-Host "     - rscm_firmware_checks.rscm_port" -ForegroundColor Gray
Write-Host "     - rscm_firmware_checks.position" -ForegroundColor Gray
Write-Host ""
Write-Host "  4. User Management Enhancements" -ForegroundColor Gray
Write-Host "     - users.role (admin/editor/viewer)" -ForegroundColor Gray
Write-Host "     - users.email, first_name, last_name, team" -ForegroundColor Gray
Write-Host "     - users.must_change_password" -ForegroundColor Gray
Write-Host "     - access_requests.username, password_hash" -ForegroundColor Gray
Write-Host ""
Write-Host "  5. Program Association" -ForegroundColor Gray
Write-Host "     - systems.program_id" -ForegroundColor Gray
Write-Host "     - firmware_recipes.program_id" -ForegroundColor Gray
Write-Host ""
Write-Host "  6. Tracking Fields" -ForegroundColor Gray
Write-Host "     - firmware_checks.user_id, recipe_id" -ForegroundColor Gray
Write-Host "     - systems.created_by" -ForegroundColor Gray
Write-Host ""
Write-Host "=" * 80 -ForegroundColor Cyan
