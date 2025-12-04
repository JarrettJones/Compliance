#!/usr/bin/env python3
"""
Local Production Deployment Script
Run this ON the production server to deploy and verify changes
"""

import sys
import sqlite3
import json
import subprocess
import time
from datetime import datetime
from pathlib import Path


def print_header(text, char="="):
    print(char * 80)
    print(text)
    print(char * 80)
    print()


def print_step(step, title):
    print(f"Step {step}: {title}")
    print("-" * 80)


def verify_database():
    """Verify database schema"""
    
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
        
        conn.close()
        return results
        
    except Exception as e:
        return {'success': False, 'error': str(e)}


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Deploy to production (run ON the server)')
    parser.add_argument('--verify-only', action='store_true', help='Only verify, do not deploy')
    parser.add_argument('--skip-backup', action='store_true', help='Skip database backup')
    
    args = parser.parse_args()
    
    print_header("PRODUCTION DEPLOYMENT SCRIPT")
    print(f"Mode: {'VERIFY ONLY' if args.verify_only else 'DEPLOY & VERIFY'}")
    print(f"Working Directory: {Path.cwd()}")
    print()
    
    if not args.verify_only:
        # Step 1: Backup database
        print_step(1, "Backing Up Database")
        
        if args.skip_backup:
            print("[SKIPPED] Backup skipped per user request")
        else:
            db_path = Path('firmware_checker.db')
            
            if not db_path.exists():
                print(f"[ERROR] Database not found: {db_path}")
                sys.exit(1)
            
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            backup_path = Path(f'firmware_checker.db.backup-{timestamp}')
            
            try:
                import shutil
                shutil.copy2(db_path, backup_path)
                size_mb = backup_path.stat().st_size / (1024 * 1024)
                print(f"[OK] Database backed up successfully")
                print(f"  Backup: {backup_path}")
                print(f"  Size: {size_mb:.2f} MB")
            except Exception as e:
                print(f"[ERROR] Backup failed: {e}")
                sys.exit(1)
        
        print()
        
        # Step 2: Stop Flask
        print_step(2, "Stopping Flask Application")
        
        try:
            # Try to find and stop Flask processes
            result = subprocess.run(
                ['powershell', '-Command', 
                 "Get-Process -Name python -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '*app.py*' } | Stop-Process -Force; Start-Sleep -Seconds 2"],
                capture_output=True,
                text=True
            )
            print("[OK] Stopped Flask processes (if any were running)")
        except Exception as e:
            print(f"[WARNING] Could not stop Flask: {e}")
        
        print()
        
        # Step 3: Pull latest changes
        print_step(3, "Pulling Latest Changes from GitHub")
        
        try:
            # Get current commit
            old_commit = subprocess.run(
                ['git', 'rev-parse', '--short', 'HEAD'],
                capture_output=True,
                text=True,
                check=True
            ).stdout.strip()
            
            # Pull changes
            subprocess.run(
                ['git', 'pull', 'origin', 'feature/improvements'],
                check=True
            )
            
            # Get new commit
            new_commit = subprocess.run(
                ['git', 'rev-parse', '--short', 'HEAD'],
                capture_output=True,
                text=True,
                check=True
            ).stdout.strip()
            
            # Get branch
            branch = subprocess.run(
                ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                capture_output=True,
                text=True,
                check=True
            ).stdout.strip()
            
            print(f"  Branch: {branch}")
            print(f"  Old Commit: {old_commit}")
            print(f"  New Commit: {new_commit}")
            
            if old_commit != new_commit:
                print("[OK] Repository updated")
            else:
                print("[OK] Already up to date")
                
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Git pull failed: {e}")
            sys.exit(1)
        
        print()
    
    # Verify database
    step_num = 4 if not args.verify_only else 1
    print_step(step_num, "Verifying Database Schema")
    
    db_check = verify_database()
    
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
            print("[INFO] Flask will automatically create missing tables/columns on startup")
    
    print()
    
    if not args.verify_only:
        # Start Flask
        step_num = 5
        print_step(step_num, "Starting Flask Application")
        print()
        print("Please start Flask manually in a new terminal:")
        print("  python app.py")
        print()
        print("Flask will automatically:")
        print("  1. Call init_db() which checks for missing tables/columns")
        print("  2. Create any missing tables with CREATE TABLE IF NOT EXISTS")
        print("  3. Add any missing columns with ALTER TABLE ADD COLUMN")
        print("  4. Migrate data from old structures if needed")
        print()
        print("Watch for log messages like:")
        print("  INFO:__main__:Added rscm_ip column to rscm_firmware_checks table")
        print("  INFO:__main__:Added rscm_port column to rscm_firmware_checks table")
        print("  INFO:__main__:Added position column to rscm_firmware_checks table")
        print()
        
        response = input("Start Flask now and press Enter when it's running (or Ctrl+C to exit)...")
        
        # Final verification
        print()
        print_step(6, "Final Database Verification")
        
        time.sleep(2)  # Give Flask a moment
        
        final_check = verify_database()
        
        if final_check.get('success'):
            print("[OK] Database migration completed successfully!")
            print("  All critical columns verified")
        else:
            print("[WARNING] Database still incomplete")
            if final_check.get('missing_columns'):
                print("  Missing columns:")
                for table, cols in final_check['missing_columns'].items():
                    print(f"    {table}: {', '.join(cols)}")
        
        print()
    
    # Summary
    print_header("DEPLOYMENT COMPLETE" if not args.verify_only else "VERIFICATION COMPLETE")
    
    if not args.verify_only:
        print("Next Steps:")
        print("  1. Access: https://dca20301103n414/firmware-checker/")
        print("  2. Log in and test RSCM firmware checks")
        print("  3. Monitor Flask console for any errors")
        print()
    
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[CANCELLED] Deployment cancelled by user")
        sys.exit(1)
