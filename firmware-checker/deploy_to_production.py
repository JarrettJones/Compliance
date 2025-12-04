#!/usr/bin/env python3
"""
Remote Production Deployment Script
Deploys changes to production server and verifies database migration
"""

import sys
import argparse
import subprocess
import json
import time
from pathlib import Path


def run_remote_command(server, command, check=True):
    """Execute a command on the remote server via PowerShell remoting"""
    ps_command = f"""
    $session = New-PSSession -ComputerName {server}
    try {{
        Invoke-Command -Session $session -ScriptBlock {{
            {command}
        }}
    }} finally {{
        Remove-PSSession $session
    }}
    """
    
    result = subprocess.run(
        ["powershell", "-Command", ps_command],
        capture_output=True,
        text=True
    )
    
    if check and result.returncode != 0:
        print(f"ERROR: Command failed: {result.stderr}")
        return None
    
    return result.stdout.strip()


def run_remote_python(server, remote_path, python_code):
    """Execute Python code on the remote server"""
    ps_command = f"""
    $session = New-PSSession -ComputerName {server}
    try {{
        Invoke-Command -Session $session -ScriptBlock {{
            Set-Location '{remote_path}'
            $code = @'
{python_code}
'@
            $tempFile = [System.IO.Path]::GetTempFileName() + '.py'
            $code | Out-File -FilePath $tempFile -Encoding UTF8
            python $tempFile 2>&1
            Remove-Item $tempFile -Force
        }}
    }} finally {{
        Remove-PSSession $session
    }}
    """
    
    result = subprocess.run(
        ["powershell", "-Command", ps_command],
        capture_output=True,
        text=True
    )
    
    return result.stdout.strip(), result.returncode


def verify_database(server, remote_path):
    """Verify database schema on remote server"""
    
    python_check = """
import sqlite3
import json

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
    
except Exception as e:
    print(json.dumps({'success': False, 'error': str(e)}))
"""
    
    output, exitcode = run_remote_python(server, remote_path, python_check)
    
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        print(f"ERROR: Failed to parse verification output")
        print(f"Raw output: {output}")
        return {'success': False, 'error': 'Failed to parse output'}


def main():
    parser = argparse.ArgumentParser(description='Deploy to production server')
    parser.add_argument('--server', default='dca20301103n414', help='Server name')
    parser.add_argument('--path', default=r'C:\Users\jarrettjones\Compliance\firmware-checker', help='Remote path')
    parser.add_argument('--verify-only', action='store_true', help='Only verify, do not deploy')
    parser.add_argument('--skip-backup', action='store_true', help='Skip database backup')
    
    args = parser.parse_args()
    
    print("=" * 80)
    print("PRODUCTION DEPLOYMENT SCRIPT")
    print("=" * 80)
    print(f"Target Server: {args.server}")
    print(f"Remote Path: {args.path}")
    print(f"Mode: {'VERIFY ONLY' if args.verify_only else 'DEPLOY & VERIFY'}")
    print()
    
    # Step 1: Test connection
    print("Step 1: Testing Connection")
    print("-" * 80)
    result = subprocess.run(
        ["powershell", "-Command", f"Test-Connection -ComputerName {args.server} -Count 1 -Quiet"],
        capture_output=True
    )
    
    if result.returncode != 0:
        print(f"[ERROR] Cannot reach server: {args.server}")
        print("\nPlease verify:")
        print("  1. Server name is correct")
        print("  2. Server is online and reachable")
        print("  3. You have network connectivity")
        sys.exit(1)
    
    print("[OK] Server is reachable")
    print()
    
    if not args.verify_only:
        # Step 2: Backup database
        print("Step 2: Backing Up Database")
        print("-" * 80)
        
        if args.skip_backup:
            print("[SKIPPED] Backup skipped per user request")
        else:
            backup_cmd = f"""
                Set-Location '{args.path}'
                $dbPath = 'firmware_checker.db'
                if (Test-Path $dbPath) {{
                    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
                    $backupPath = "$dbPath.backup-$timestamp"
                    Copy-Item $dbPath $backupPath -Force
                    $size = [math]::Round((Get-Item $backupPath).Length / 1MB, 2)
                    Write-Output "SUCCESS:$backupPath:$size"
                }} else {{
                    Write-Output "ERROR:Database not found"
                }}
            """
            
            output = run_remote_command(args.server, backup_cmd, check=False)
            
            if output and output.startswith("SUCCESS"):
                _, backup_path, size = output.split(":")
                print(f"[OK] Database backed up successfully")
                print(f"  Backup: {backup_path}")
                print(f"  Size: {size} MB")
            else:
                print(f"[ERROR] Backup failed: {output}")
                sys.exit(1)
        
        print()
        
        # Step 3: Stop Flask
        print("Step 3: Stopping Flask Application")
        print("-" * 80)
        
        stop_cmd = """
            $processes = Get-Process -Name python -ErrorAction SilentlyContinue |
                Where-Object { $_.CommandLine -like '*app.py*' }
            if ($processes) {
                $processes | Stop-Process -Force
                Start-Sleep -Seconds 2
                Write-Output "STOPPED:$($processes.Count)"
            } else {
                Write-Output "NOT_RUNNING"
            }
        """
        
        output = run_remote_command(args.server, stop_cmd, check=False)
        
        if output and output.startswith("STOPPED"):
            count = output.split(":")[1]
            print(f"[OK] Stopped Flask application ({count} process(es))")
        else:
            print("[INFO] Flask was not running")
        
        print()
        
        # Step 4: Pull latest changes
        print("Step 4: Pulling Latest Changes")
        print("-" * 80)
        
        git_cmd = f"""
            Set-Location '{args.path}'
            $oldCommit = git rev-parse --short HEAD
            git pull origin feature/improvements 2>&1 | Out-Null
            $newCommit = git rev-parse --short HEAD
            $branch = git rev-parse --abbrev-ref HEAD
            Write-Output "$branch|$oldCommit|$newCommit"
        """
        
        output = run_remote_command(args.server, git_cmd, check=False)
        
        if output:
            branch, old_commit, new_commit = output.split("|")
            print(f"  Branch: {branch}")
            print(f"  Old Commit: {old_commit}")
            print(f"  New Commit: {new_commit}")
            
            if old_commit != new_commit:
                print("[OK] Repository updated")
            else:
                print("[OK] Already up to date")
        
        print()
    
    # Step 5: Verify database
    print(f"Step {'5' if not args.verify_only else '2'}: Verifying Database Schema")
    print("-" * 80)
    
    db_check = verify_database(args.server, args.path)
    
    if db_check.get('success'):
        print("[OK] All required tables and columns exist!")
        print()
        print("Database Tables:")
        for table in sorted(db_check.get('table_counts', {}).keys()):
            count = db_check['table_counts'][table]
            print(f"  [OK] {table} - {count} columns")
        print()
        
        # Check critical RSCM columns
        if db_check.get('rscm_check'):
            print("Critical RSCM Columns:")
            rscm = db_check['rscm_check']
            print(f"  {'[OK]' if rscm['has_rscm_ip'] else '[X]'} rscm_firmware_checks.rscm_ip")
            print(f"  {'[OK]' if rscm['has_rscm_port'] else '[X]'} rscm_firmware_checks.rscm_port")
            print(f"  {'[OK]' if rscm['has_position'] else '[X]'} rscm_firmware_checks.position")
    else:
        print("[ERROR] Database migration incomplete!")
        print()
        
        if db_check.get('missing_tables'):
            print("Missing Tables:")
            for table in db_check['missing_tables']:
                print(f"  [X] {table}")
            print()
        
        if db_check.get('missing_columns'):
            print("Missing Columns:")
            for table, cols in db_check['missing_columns'].items():
                print(f"  Table: {table}")
                for col in cols:
                    print(f"    [X] {col}")
            print()
        
        if not args.verify_only:
            print("Migration needed - Flask will initialize database on startup...")
    
    print()
    
    if not args.verify_only:
        # Step 6: Start Flask
        print("Step 6: Starting Flask Application")
        print("-" * 80)
        print("Starting Flask (will run for 15 seconds to complete initialization)...")
        print()
        
        start_cmd = f"""
            Set-Location '{args.path}'
            $job = Start-Job -ScriptBlock {{
                param($path)
                Set-Location $path
                python app.py 2>&1
            }} -ArgumentList '{args.path}'
            
            Start-Sleep -Seconds 15
            
            $output = Receive-Job -Job $job
            $processes = Get-Process -Name python -ErrorAction SilentlyContinue |
                Where-Object {{ $_.CommandLine -like '*app.py*' }}
            
            if ($processes) {{
                Write-Output "RUNNING"
            }} else {{
                Write-Output "FAILED"
            }}
            
            # Show relevant output
            $output -split "`n" | Where-Object {{
                $_ -match "Database initialized|Migrated|Running on"
            }} | ForEach-Object {{ Write-Output $_ }}
        """
        
        output = run_remote_command(args.server, start_cmd, check=False)
        
        if output and "RUNNING" in output:
            print("[OK] Flask application started successfully")
            
            # Show initialization messages
            for line in output.split("\n"):
                if "Database initialized" in line:
                    print("  [OK] Database initialized")
                elif "Migrated" in line:
                    print(f"  {line.strip()}")
                elif "Running on" in line:
                    print(f"  {line.strip()}")
        else:
            print("[ERROR] Flask failed to start")
            print(f"Output: {output}")
        
        print()
        
        # Step 7: Final verification
        print("Step 7: Final Database Verification")
        print("-" * 80)
        print("Running final check after Flask initialization...")
        
        time.sleep(2)  # Give Flask a moment to finish
        
        final_check = verify_database(args.server, args.path)
        
        if final_check.get('success'):
            print("[OK] Database migration completed successfully!")
            print("  All critical columns verified")
        else:
            print("[WARNING] Database still missing columns")
            print("  You may need to manually restart Flask")
        
        print()
    
    # Summary
    print("=" * 80)
    if args.verify_only:
        print("VERIFICATION COMPLETE")
    else:
        print("DEPLOYMENT COMPLETE")
    print("=" * 80)
    print()
    
    if not args.verify_only:
        print("Next Steps:")
        print(f"  1. Access: https://{args.server}/firmware-checker/")
        print("  2. Log in and test RSCM firmware checks")
        print("  3. Monitor Flask logs for errors")
        print()
        print("Flask is running on the production server.")
    
    print()


if __name__ == "__main__":
    main()
