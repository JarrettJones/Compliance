# Remote Production Deployment Script
# This script deploys changes to the production server and verifies the migration

param(
    [Parameter(Mandatory=$false)]
    [string]$ServerName = "dca20301103n414",
    
    [Parameter(Mandatory=$false)]
    [string]$RemotePath = "C:\Users\jarrettjones\Compliance\firmware-checker",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipBackup = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$VerifyOnly = $false
)

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "PRODUCTION DEPLOYMENT SCRIPT" -ForegroundColor Yellow
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""
Write-Host "Target Server: $ServerName" -ForegroundColor White
Write-Host "Remote Path: $RemotePath" -ForegroundColor White
Write-Host "Mode: $(if ($VerifyOnly) { 'VERIFY ONLY' } else { 'DEPLOY & VERIFY' })" -ForegroundColor $(if ($VerifyOnly) { 'Yellow' } else { 'Green' })
Write-Host ""

# Test connection to server
Write-Host "Step 1: Testing Connection to Production Server" -ForegroundColor Cyan
Write-Host "-" * 80

try {
    $testConnection = Test-Connection -ComputerName $ServerName -Count 1 -Quiet
    if (-not $testConnection) {
        Write-Host "[ERROR] Cannot reach server: $ServerName" -ForegroundColor Red
        Write-Host ""
        Write-Host "Please verify:" -ForegroundColor Yellow
        Write-Host "  1. Server name is correct" -ForegroundColor White
        Write-Host "  2. Server is online and reachable" -ForegroundColor White
        Write-Host "  3. You have network connectivity" -ForegroundColor White
        exit 1
    }
    Write-Host "[OK] Server is reachable" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Connection test failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Create remote session
Write-Host "Step 2: Creating Remote PowerShell Session" -ForegroundColor Cyan
Write-Host "-" * 80

try {
    $session = New-PSSession -ComputerName $ServerName -ErrorAction Stop
    Write-Host "[OK] Remote session established" -ForegroundColor Green
    Write-Host "  Session ID: $($session.Id)" -ForegroundColor Gray
} catch {
    Write-Host "[ERROR] Failed to create remote session: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Possible solutions:" -ForegroundColor Yellow
    Write-Host "  1. Enable PowerShell Remoting on the server: Enable-PSRemoting -Force" -ForegroundColor White
    Write-Host "  2. Add server to trusted hosts: Set-Item WSMan:\localhost\Client\TrustedHosts -Value '$ServerName' -Force" -ForegroundColor White
    Write-Host "  3. Ensure WinRM service is running on the server" -ForegroundColor White
    exit 1
}
Write-Host ""

try {
    if (-not $VerifyOnly) {
        # Step 3: Backup Database
        Write-Host "Step 3: Backing Up Production Database" -ForegroundColor Cyan
        Write-Host "-" * 80
        
        if ($SkipBackup) {
            Write-Host "[SKIPPED] Backup skipped per user request" -ForegroundColor Yellow
        } else {
            $backupResult = Invoke-Command -Session $session -ScriptBlock {
                param($path)
                
                $dbPath = Join-Path $path "firmware_checker.db"
                
                if (-not (Test-Path $dbPath)) {
                    return @{
                        Success = $false
                        Error = "Database not found at: $dbPath"
                    }
                }
                
                $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
                $backupPath = "$dbPath.backup-$timestamp"
                
                try {
                    Copy-Item $dbPath $backupPath -Force
                    $backupSize = (Get-Item $backupPath).Length / 1MB
                    
                    return @{
                        Success = $true
                        BackupPath = $backupPath
                        BackupSize = [math]::Round($backupSize, 2)
                    }
                } catch {
                    return @{
                        Success = $false
                        Error = $_.Exception.Message
                    }
                }
            } -ArgumentList $RemotePath
            
            if ($backupResult.Success) {
                Write-Host "[OK] Database backed up successfully" -ForegroundColor Green
                Write-Host "  Backup: $($backupResult.BackupPath)" -ForegroundColor Gray
                Write-Host "  Size: $($backupResult.BackupSize) MB" -ForegroundColor Gray
            } else {
                Write-Host "[ERROR] Backup failed: $($backupResult.Error)" -ForegroundColor Red
                Write-Host "Aborting deployment..." -ForegroundColor Yellow
                Remove-PSSession $session
                exit 1
            }
        }
        Write-Host ""
        
        # Step 4: Stop Flask Application
        Write-Host "Step 4: Stopping Flask Application" -ForegroundColor Cyan
        Write-Host "-" * 80
        
        $stopResult = Invoke-Command -Session $session -ScriptBlock {
            $flaskProcesses = Get-Process -Name "python" -ErrorAction SilentlyContinue | 
                Where-Object { $_.CommandLine -like "*app.py*" }
            
            if ($flaskProcesses) {
                $count = ($flaskProcesses | Measure-Object).Count
                $flaskProcesses | Stop-Process -Force
                Start-Sleep -Seconds 2
                return @{
                    WasRunning = $true
                    ProcessCount = $count
                }
            } else {
                return @{
                    WasRunning = $false
                    ProcessCount = 0
                }
            }
        }
        
        if ($stopResult.WasRunning) {
            Write-Host "[OK] Stopped Flask application ($($stopResult.ProcessCount) process(es))" -ForegroundColor Green
        } else {
            Write-Host "[INFO] Flask was not running" -ForegroundColor Yellow
        }
        Write-Host ""
        
        # Step 5: Pull Latest Changes from Git
        Write-Host "Step 5: Pulling Latest Changes from GitHub" -ForegroundColor Cyan
        Write-Host "-" * 80
        
        $gitResult = Invoke-Command -Session $session -ScriptBlock {
            param($path)
            
            Set-Location $path
            
            # Get current commit
            $oldCommit = (git rev-parse --short HEAD 2>&1)
            
            # Pull changes
            $pullOutput = git pull origin feature/improvements 2>&1
            
            # Get new commit
            $newCommit = (git rev-parse --short HEAD 2>&1)
            
            # Get branch
            $branch = (git rev-parse --abbrev-ref HEAD 2>&1)
            
            return @{
                OldCommit = $oldCommit
                NewCommit = $newCommit
                Branch = $branch
                Output = $pullOutput -join "`n"
                Updated = ($oldCommit -ne $newCommit)
            }
        } -ArgumentList $RemotePath
        
        Write-Host "  Branch: $($gitResult.Branch)" -ForegroundColor White
        Write-Host "  Old Commit: $($gitResult.OldCommit)" -ForegroundColor Gray
        Write-Host "  New Commit: $($gitResult.NewCommit)" -ForegroundColor Gray
        
        if ($gitResult.Updated) {
            Write-Host "[OK] Repository updated" -ForegroundColor Green
        } else {
            Write-Host "[OK] Already up to date" -ForegroundColor Green
        }
        Write-Host ""
    }
    
    # Step 6: Verify Database Migration
    Write-Host "Step 6: Verifying Database Schema" -ForegroundColor Cyan
    Write-Host "-" * 80
    
    $verifyResult = Invoke-Command -Session $session -ScriptBlock {
        param($path)
        
        Set-Location $path
        
        # Python script to verify database
        $pythonScript = @'
import sqlite3
import json
import sys

required_tables = {
    'programs': ['id', 'name', 'description', 'check_methodology', 'is_active'],
    'locations': ['id', 'name', 'description'],
    'buildings': ['id', 'location_id', 'name'],
    'rooms': ['id', 'building_id', 'name'],
    'racks': ['id', 'name', 'room_id', 'rack_type', 'rscm_upper_ip', 'rscm_lower_ip', 'rscm_ip'],
    'systems': ['id', 'name', 'rscm_ip', 'rscm_port', 'program_id', 'created_by'],
    'firmware_checks': ['id', 'system_id', 'check_date', 'firmware_data', 'status', 'user_id', 'recipe_id'],
    'rscm_firmware_checks': ['id', 'rack_id', 'rscm_ip', 'rscm_port', 'position', 'check_date', 'firmware_data', 'status', 'user_id'],
    'firmware_types': ['id', 'category', 'name', 'description'],
    'program_firmware_types': ['program_id', 'firmware_type_id'],
    'program_custom_fields': ['id', 'program_id', 'field_name', 'field_label', 'field_type', 'is_required'],
    'system_custom_field_values': ['id', 'system_id', 'field_id', 'field_value'],
    'firmware_recipes': ['id', 'name', 'description', 'firmware_versions', 'program_id'],
    'users': ['id', 'username', 'password_hash', 'role', 'is_active', 'email', 'first_name', 'last_name', 'team', 'must_change_password'],
    'access_requests': ['id', 'email', 'first_name', 'business_justification', 'status', 'username', 'password_hash']
}

try:
    conn = sqlite3.connect('firmware_checker.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    existing_tables = [row[0] for row in cursor.fetchall()]
    
    results = {
        'success': True,
        'missing_tables': [],
        'missing_columns': {},
        'table_counts': {}
    }
    
    for table, required_cols in required_tables.items():
        if table not in existing_tables:
            results['missing_tables'].append(table)
            results['success'] = False
            continue
        
        cursor.execute(f"PRAGMA table_info({table})")
        existing_cols = [row[1] for row in cursor.fetchall()]
        results['table_counts'][table] = len(existing_cols)
        
        missing = [col for col in required_cols if col not in existing_cols]
        if missing:
            results['missing_columns'][table] = missing
            results['success'] = False
    
    # Special check for rscm_firmware_checks critical columns
    if 'rscm_firmware_checks' in existing_tables:
        cursor.execute("PRAGMA table_info(rscm_firmware_checks)")
        rscm_cols = [row[1] for row in cursor.fetchall()]
        results['rscm_check'] = {
            'has_rscm_ip': 'rscm_ip' in rscm_cols,
            'has_rscm_port': 'rscm_port' in rscm_cols,
            'has_position': 'position' in rscm_cols
        }
    
    print(json.dumps(results))
    conn.close()
    sys.exit(0 if results['success'] else 1)
    
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
    sys.exit(1)
'@
        
        # Save script to temp file
        $tempScript = [System.IO.Path]::GetTempFileName() + ".py"
        $pythonScript | Out-File -FilePath $tempScript -Encoding UTF8
        
        # Run verification
        $output = python $tempScript 2>&1
        $exitCode = $LASTEXITCODE
        
        # Clean up
        Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
        
        return @{
            Output = $output
            ExitCode = $exitCode
        }
    } -ArgumentList $RemotePath
    
    # Parse results
    try {
        $dbCheck = $verifyResult.Output | ConvertFrom-Json
        
        if ($dbCheck.success) {
            Write-Host "[OK] All required tables and columns exist!" -ForegroundColor Green
            Write-Host ""
            Write-Host "Database Tables:" -ForegroundColor White
            foreach ($table in ($dbCheck.table_counts.Keys | Sort-Object)) {
                $count = $dbCheck.table_counts.$table
                Write-Host "  ✓ $table" -ForegroundColor Green -NoNewline
                Write-Host " ($count columns)" -ForegroundColor Gray
            }
            Write-Host ""
            
            # Verify critical RSCM columns
            if ($dbCheck.rscm_check) {
                Write-Host "Critical RSCM Columns:" -ForegroundColor White
                if ($dbCheck.rscm_check.has_rscm_ip) {
                    Write-Host "  ✓ rscm_firmware_checks.rscm_ip" -ForegroundColor Green
                } else {
                    Write-Host "  ✗ rscm_firmware_checks.rscm_ip" -ForegroundColor Red
                }
                
                if ($dbCheck.rscm_check.has_rscm_port) {
                    Write-Host "  ✓ rscm_firmware_checks.rscm_port" -ForegroundColor Green
                } else {
                    Write-Host "  ✗ rscm_firmware_checks.rscm_port" -ForegroundColor Red
                }
                
                if ($dbCheck.rscm_check.has_position) {
                    Write-Host "  ✓ rscm_firmware_checks.position" -ForegroundColor Green
                } else {
                    Write-Host "  ✗ rscm_firmware_checks.position" -ForegroundColor Red
                }
            }
            
        } else {
            Write-Host "[ERROR] Database migration incomplete!" -ForegroundColor Red
            Write-Host ""
            
            if ($dbCheck.missing_tables -and $dbCheck.missing_tables.Count -gt 0) {
                Write-Host "Missing Tables:" -ForegroundColor Red
                foreach ($table in $dbCheck.missing_tables) {
                    Write-Host "  ✗ $table" -ForegroundColor Yellow
                }
                Write-Host ""
            }
            
            if ($dbCheck.missing_columns) {
                Write-Host "Missing Columns:" -ForegroundColor Red
                $tableNames = $dbCheck.missing_columns.PSObject.Properties.Name
                foreach ($table in $tableNames) {
                    Write-Host "  Table: $table" -ForegroundColor Yellow
                    foreach ($col in $dbCheck.missing_columns.$table) {
                        Write-Host "    ✗ $col" -ForegroundColor Gray
                    }
                }
                Write-Host ""
            }
            
            if (-not $VerifyOnly) {
                Write-Host "Migration needed - will start Flask to initialize database..." -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "[ERROR] Failed to parse verification results: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Raw output:" -ForegroundColor Yellow
        Write-Host $verifyResult.Output -ForegroundColor Gray
    }
    Write-Host ""
    
    if (-not $VerifyOnly) {
        # Step 7: Start Flask Application
        Write-Host "Step 7: Starting Flask Application" -ForegroundColor Cyan
        Write-Host "-" * 80
        
        Write-Host "Starting Flask application (this will initialize the database)..." -ForegroundColor Yellow
        Write-Host "Note: Flask will run for 10 seconds to complete initialization, then we'll verify again." -ForegroundColor Gray
        Write-Host ""
        
        $flaskResult = Invoke-Command -Session $session -ScriptBlock {
            param($path)
            
            Set-Location $path
            
            # Start Flask in background
            $job = Start-Job -ScriptBlock {
                param($workingDir)
                Set-Location $workingDir
                python app.py 2>&1
            } -ArgumentList $path
            
            # Wait for initialization (10 seconds)
            Start-Sleep -Seconds 10
            
            # Check if Flask is running
            $flaskProcess = Get-Process -Name "python" -ErrorAction SilentlyContinue | 
                Where-Object { $_.CommandLine -like "*app.py*" }
            
            $isRunning = $flaskProcess -ne $null
            
            # Get job output
            $output = Receive-Job -Job $job
            
            return @{
                IsRunning = $isRunning
                Output = $output -join "`n"
            }
        } -ArgumentList $RemotePath
        
        if ($flaskResult.IsRunning) {
            Write-Host "[OK] Flask application started successfully" -ForegroundColor Green
            
            # Show initialization output
            if ($flaskResult.Output -match "Database initialized successfully") {
                Write-Host "  ✓ Database initialized" -ForegroundColor Green
            }
            if ($flaskResult.Output -match "Migrated.*rack") {
                $migrations = $flaskResult.Output -split "`n" | Where-Object { $_ -match "Migrated" }
                foreach ($migration in $migrations) {
                    Write-Host "  $migration" -ForegroundColor Gray
                }
            }
        } else {
            Write-Host "[ERROR] Flask failed to start" -ForegroundColor Red
            Write-Host "Output:" -ForegroundColor Yellow
            Write-Host $flaskResult.Output -ForegroundColor Gray
        }
        Write-Host ""
        
        # Step 8: Final Verification
        Write-Host "Step 8: Final Database Verification" -ForegroundColor Cyan
        Write-Host "-" * 80
        
        Write-Host "Running final verification after Flask initialization..." -ForegroundColor Yellow
        
        $finalVerify = Invoke-Command -Session $session -ScriptBlock {
            param($path)
            Set-Location $path
            
            # Use the same Python script as before
            $pythonScript = @'
import sqlite3
import json

try:
    conn = sqlite3.connect('firmware_checker.db')
    cursor = conn.cursor()
    
    # Check critical columns
    cursor.execute("PRAGMA table_info(rscm_firmware_checks)")
    cols = [row[1] for row in cursor.fetchall()]
    
    has_all = all(c in cols for c in ['rscm_ip', 'rscm_port', 'position'])
    
    print(json.dumps({
        'success': has_all,
        'columns': cols
    }))
    conn.close()
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
'@
            $tempScript = [System.IO.Path]::GetTempFileName() + ".py"
            $pythonScript | Out-File -FilePath $tempScript -Encoding UTF8
            $output = python $tempScript 2>&1
            Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
            return $output
        } -ArgumentList $RemotePath
        
        $finalCheck = $finalVerify | ConvertFrom-Json
        
        if ($finalCheck.success) {
            Write-Host "[OK] ✓ Database migration completed successfully!" -ForegroundColor Green
            Write-Host "  All critical columns verified" -ForegroundColor Gray
        } else {
            Write-Host "[WARNING] Database still missing columns" -ForegroundColor Yellow
            Write-Host "  You may need to manually restart Flask to complete migration" -ForegroundColor Gray
        }
        Write-Host ""
    }
    
    # Summary
    Write-Host "=" * 80 -ForegroundColor Cyan
    if ($VerifyOnly) {
        Write-Host "VERIFICATION COMPLETE" -ForegroundColor Yellow
    } else {
        Write-Host "DEPLOYMENT COMPLETE" -ForegroundColor Green
    }
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host ""
    
    if (-not $VerifyOnly) {
        Write-Host "Next Steps:" -ForegroundColor Yellow
        Write-Host "  1. Access the application: https://$ServerName/firmware-checker/" -ForegroundColor White
        Write-Host "  2. Log in and test RSCM firmware checks" -ForegroundColor White
        Write-Host "  3. Monitor Flask logs for any errors" -ForegroundColor White
        Write-Host ""
        Write-Host "Flask is running on the production server." -ForegroundColor Green
        Write-Host "To stop Flask: Connect to server and run: Get-Process -Name python | Where-Object { `$_.CommandLine -like '*app.py*' } | Stop-Process" -ForegroundColor Gray
    }
    Write-Host ""
    
} finally {
    # Clean up session
    if ($session) {
        Remove-PSSession $session
        Write-Host "Remote session closed." -ForegroundColor Gray
    }
}

Write-Host "=" * 80 -ForegroundColor Cyan
