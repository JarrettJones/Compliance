#!/usr/bin/env python3
"""
Firmware Version Checker Web Application
A Flask-based web application for checking and recording firmware versions
from various systems including DC-SCM, OVL2, and other platform firmwares.
"""

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.wrappers import Response
import sqlite3
import os
from datetime import datetime
import logging
from contextlib import contextmanager
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# Import firmware checking modules
from firmware_modules.dc_scm import DCScmChecker
from firmware_modules.ovl2 import OVL2Checker  
from firmware_modules.other_platform import OtherPlatformChecker

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Middleware to handle reverse proxy headers and path prefixes
class PrefixMiddleware:
    """Middleware to handle X-Script-Name for proper URL generation behind reverse proxy"""
    def __init__(self, app, prefix=''):
        self.app = app
        self.prefix = prefix

    def __call__(self, environ, start_response):
        # Check for X-Script-Name header from nginx
        script_name = environ.get('HTTP_X_SCRIPT_NAME', '')
        if script_name:
            logger.info(f"[PREFIX-MW] Setting SCRIPT_NAME from X-Script-Name: {script_name}")
            environ['SCRIPT_NAME'] = script_name
            
        # Also support X-Forwarded-Prefix
        forwarded_prefix = environ.get('HTTP_X_FORWARDED_PREFIX', '')
        if forwarded_prefix and not script_name:
            logger.info(f"[PREFIX-MW] Setting SCRIPT_NAME from X-Forwarded-Prefix: {forwarded_prefix}")
            environ['SCRIPT_NAME'] = forwarded_prefix
        
        # Debug logging
        if not script_name and not forwarded_prefix:
            logger.warning(f"[PREFIX-MW] No prefix headers found! PATH_INFO: {environ.get('PATH_INFO')}")
            
        return self.app(environ, start_response)

# Apply middleware - ProxyFix first, then PrefixMiddleware
# ProxyFix handles X-Forwarded-* headers but doesn't handle X-Script-Name
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=0)
app.wsgi_app = PrefixMiddleware(app.wsgi_app)

# Security: Use environment variable for secret key
# Generate one with: python generate_secret_key.py
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    logger.critical("=" * 80)
    logger.critical("SECURITY WARNING: No SECRET_KEY environment variable set!")
    logger.critical("Using an insecure fallback key. This is NOT safe for production.")
    logger.critical("Generate a secure key with: python generate_secret_key.py")
    logger.critical("Then set it in your .env file or environment variables.")
    logger.critical("=" * 80)
    SECRET_KEY = 'INSECURE-FALLBACK-KEY-DO-NOT-USE-IN-PRODUCTION'

app.secret_key = SECRET_KEY

# Configuration
DATABASE = 'firmware_checker.db'
UPLOAD_FOLDER = 'uploads'

# Thread management for background firmware checks
thread_pool = ThreadPoolExecutor(max_workers=10)  # Allow up to 10 concurrent firmware checks
active_checks_lock = threading.Lock()
active_checks = {}  # Maps check_id to thread info

@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = sqlite3.connect(DATABASE, timeout=30.0)  # Increase timeout to handle concurrent access
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')  # Enable Write-Ahead Logging for better concurrency
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    """Initialize the database with required tables"""
    with get_db_connection() as conn:
        # Systems table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS systems (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                rscm_ip TEXT NOT NULL,
                rscm_port INTEGER NOT NULL DEFAULT 22,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Firmware checks table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS firmware_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                system_id INTEGER NOT NULL,
                check_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                firmware_data TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'success',
                error_message TEXT,
                FOREIGN KEY (system_id) REFERENCES systems (id)
            )
        ''')
        
        # Firmware types table for reference
        conn.execute('''
            CREATE TABLE IF NOT EXISTS firmware_types (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT
            )
        ''')
        
        # Firmware recipes table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS firmware_recipes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                firmware_versions TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Add recipe_id column to firmware_checks if it doesn't exist
        try:
            conn.execute('ALTER TABLE firmware_checks ADD COLUMN recipe_id INTEGER')
        except:
            pass  # Column already exists
        
        conn.commit()
        
        # Insert firmware types if they don't exist
        firmware_types = [
            # DC-SCM firmware types
            ('DC-SCM', 'IFWI', 'Intel Firmware Interface'),
            ('DC-SCM', 'UEFI Profile/Other', 'UEFI Profile/Other'),
            ('DC-SCM', 'BMC FW', 'Baseboard Management Controller Firmware'),
            ('DC-SCM', 'Inventory', 'System Inventory'),
            ('DC-SCM', 'PowerCapping', 'Power Capping Configuration'),
            ('DC-SCM', 'FanTable', 'Fan Control Table'),
            ('DC-SCM', 'SDRGenerator', 'Sensor Data Record Generator'),
            ('DC-SCM', 'IPMIAllowList', 'IPMI Allow List'),
            ('DC-SCM', 'BMC Tip', 'BMC Tip'),
            ('DC-SCM', 'BMC TIP PCD Platform ID', 'BMC TIP PCD Platform ID'),
            ('DC-SCM', 'BMC TIP PCD Version ID (hex)/(dec)', 'BMC TIP PCD Version ID'),
            ('DC-SCM', 'Manticore (HSM)', 'Manticore Hardware Security Module'),
            ('DC-SCM', 'CFM Platform ID', 'CFM Platform ID'),
            ('DC-SCM', 'CFM Version ID (hex)/(dec)', 'CFM Version ID'),
            ('DC-SCM', 'TPM Module', 'Trusted Platform Module'),
            ('DC-SCM', 'SCM-CPLD', 'SCM Complex Programmable Logic Device'),
            
            # Other Platform FWs
            ('Other Platform', 'HPMCpld', 'HPM Complex Programmable Logic Device'),
            ('Other Platform', 'SOC VR Configs', 'SOC Voltage Regulator Configurations'),
            ('Other Platform', 'E.1s', 'E.1s Storage'),
            ('Other Platform', 'M.2', 'M.2 Storage'),
            
            # OVL2 firmware types
            ('OVL2', 'FPGA Agilex (App Image w/ OpRom)', 'FPGA Agilex Application Image with Option ROM'),
            ('OVL2', 'Cyclone V Image', 'Cyclone V FPGA Image'),
            ('OVL2', 'Cyclone V PFMID', 'Cyclone V Platform Firmware ID'),
            ('OVL2', 'OVL SOC FIP', 'OVL SOC Firmware Image Package'),
            ('OVL2', 'OVL SOC FIP PFMID', 'OVL SOC FIP Platform Firmware ID'),
            ('OVL2', 'SOC Test OS (STOS)', 'SOC Test Operating System'),
            ('OVL2', 'Host FPGA Driver & Tools', 'Host FPGA Driver and Tools'),
            ('OVL2', 'SOC FPGA Driver', 'SOC FPGA Driver'),
            ('OVL2', 'MANA Driver (Windows)', 'MANA Driver for Windows'),
            ('OVL2', 'Glacier Cerberus FW', 'Glacier Cerberus Firmware'),
            ('OVL2', 'Glacier Cerberus Utility', 'Glacier Cerberus Utility'),
            ('OVL2', 'Glacier Peak CFM', 'Glacier Peak Configuration Management'),
        ]
        
        # Check if firmware types already exist
        existing = conn.execute('SELECT COUNT(*) as count FROM firmware_types').fetchone()
        if existing['count'] == 0:
            conn.executemany(
                'INSERT INTO firmware_types (category, name, description) VALUES (?, ?, ?)',
                firmware_types
            )
            conn.commit()

def cleanup_orphaned_checks():
    """Clean up orphaned 'running' firmware checks on server startup"""
    from datetime import datetime, timedelta
    
    print("Checking for orphaned firmware checks...")
    
    try:
        with get_db_connection() as conn:
            # Find all checks that have been 'running' for more than 2 hours
            # This is a reasonable timeout since normal checks take 10-20 minutes
            timeout_threshold = datetime.now() - timedelta(hours=2)
            
            orphaned_checks = conn.execute('''
                SELECT id, system_id, check_date, 
                       (julianday('now') - julianday(check_date)) * 24 * 60 as minutes_running
                FROM firmware_checks 
                WHERE status = 'running' 
                AND check_date < ?
            ''', (timeout_threshold.isoformat(),)).fetchall()
            
            if orphaned_checks:
                print(f"Found {len(orphaned_checks)} orphaned running check(s):")
                
                for check in orphaned_checks:
                    minutes = check['minutes_running']
                    hours = minutes / 60
                    print(f"  - Check ID {check['id']} (System {check['system_id']}) running for {hours:.1f} hours")
                    
                    # Get existing firmware_data and update progress if it exists
                    existing_check = conn.execute('SELECT firmware_data FROM firmware_checks WHERE id = ?', (check['id'],)).fetchone()
                    firmware_data_str = existing_check['firmware_data'] if existing_check else '{}'
                    
                    # Parse and update the progress field if it exists
                    try:
                        if firmware_data_str and firmware_data_str != '{}':
                            firmware_data = json.loads(firmware_data_str)
                            if 'progress' in firmware_data:
                                firmware_data['progress']['status'] = 'error'
                                firmware_data['progress']['current_firmware'] = 'Interrupted by server restart'
                            firmware_data_str = json.dumps(firmware_data)
                        else:
                            firmware_data_str = '{"status": "interrupted", "error": "Server restart interrupted this check"}'
                    except (json.JSONDecodeError, KeyError):
                        firmware_data_str = '{"status": "interrupted", "error": "Server restart interrupted this check"}'
                    
                    # Update the orphaned check to 'error' status
                    conn.execute('''
                        UPDATE firmware_checks 
                        SET status = 'error', 
                            error_message = 'Check was interrupted when server was restarted (orphaned process)',
                            firmware_data = ?
                        WHERE id = ?
                    ''', (firmware_data_str, check['id'],))
                
                conn.commit()
                
                # Also clean up active_checks dictionary for these orphaned checks
                with active_checks_lock:
                    for check in orphaned_checks:
                        if check['id'] in active_checks:
                            print(f"  - Removing Check ID {check['id']} from active threads tracking")
                            del active_checks[check['id']]
                
                print(f"✅ Cleaned up {len(orphaned_checks)} orphaned check(s)")
            else:
                print("✅ No orphaned checks found")
                
    except Exception as e:
        print(f"❌ Error during orphaned check cleanup: {e}")

def perform_firmware_check_threaded(check_id, system_id, system_info, username, password, os_username=None, os_password=None, selected_firmware=None):
    """
    Perform firmware check in a background thread
    
    Args:
        selected_firmware: Optional dict with selected firmware types by category
                          {'dc_scm': ['BMC FW', 'BIOS'], 'ovl2': ['Cyclone V Image'], ...}
                          If None, all firmware types are checked
    """
    start_time = time.time()
    
    try:
        with active_checks_lock:
            active_checks[check_id] = {
                'thread_id': threading.current_thread().ident,
                'start_time': start_time,
                'status': 'running',
                'current_category': 'initializing'
            }
        
        if selected_firmware:
            total_selected = sum(len(v) for v in selected_firmware.values())
            print(f"[THREAD {threading.current_thread().ident}] Starting SELECTIVE firmware check for Check ID: {check_id}, System: {system_info['name']} ({system_info['rscm_ip']}:{system_info['rscm_port']}) - {total_selected} types selected")
        else:
            print(f"[THREAD {threading.current_thread().ident}] Starting FULL firmware check for Check ID: {check_id}, System: {system_info['name']} ({system_info['rscm_ip']}:{system_info['rscm_port']})")
        
        # Initialize firmware checkers with provided credentials
        dc_scm_checker = DCScmChecker(username=username, password=password)
        ovl2_checker = OVL2Checker(username=username, password=password, 
                                   os_username=os_username, os_password=os_password)
        other_platform_checker = OtherPlatformChecker(username=username, password=password, 
                                                    os_username=os_username, os_password=os_password)
        
        # Calculate total firmware types to check
        total_fw_types = 0
        dc_scm_types_to_check = selected_firmware.get('dc_scm', dc_scm_checker.firmware_types) if selected_firmware else dc_scm_checker.firmware_types
        ovl2_types_to_check = selected_firmware.get('ovl2', ovl2_checker.firmware_types) if selected_firmware else ovl2_checker.firmware_types
        other_platform_types_to_check = selected_firmware.get('other_platform', other_platform_checker.firmware_types) if selected_firmware else other_platform_checker.firmware_types
        
        total_fw_types = len(dc_scm_types_to_check) + len(ovl2_types_to_check) + len(other_platform_types_to_check)
        
        # Initialize results structure
        results = {
            'system_id': system_id,
            'system_name': system_info['name'],
            'rscm_ip': system_info['rscm_ip'],
            'rscm_port': system_info['rscm_port'],
            'check_date': datetime.now().isoformat(),
            'check_id': check_id,
            'dc_scm': {'firmware_versions': {}},
            'ovl2': {'firmware_versions': {}},
            'other_platform': {'firmware_versions': {}},
            'progress': {
                'total': total_fw_types,
                'completed': 0,
                'percentage': 0,
                'current_category': 'DC-SCM',
                'current_firmware': 'Starting...',
                'status': 'running'
            }
        }
        
        # Update progress in database with initial structure
        with get_db_connection() as conn:
            conn.execute('''
                UPDATE firmware_checks 
                SET firmware_data = ?
                WHERE id = ?
            ''', (json.dumps(results), check_id))
            conn.commit()
        
        # Check DC-SCM firmware individually
        with active_checks_lock:
            active_checks[check_id]['current_category'] = 'DC-SCM'
        
        # Determine which DC-SCM firmware types to check (already calculated above)
        print(f"[THREAD {threading.current_thread().ident}] Checking DC-SCM firmware ({len(dc_scm_types_to_check)} types)...")
        
        for i, fw_type in enumerate(dc_scm_types_to_check, 1):
            # Update progress
            results['progress']['current_category'] = 'DC-SCM'
            results['progress']['current_firmware'] = fw_type
            results['progress']['completed'] = results['progress']['completed']
            results['progress']['percentage'] = int((results['progress']['completed'] / total_fw_types) * 100)
            
            print(f"[THREAD {threading.current_thread().ident}] DC-SCM ({i}/{len(dc_scm_types_to_check)}): Checking {fw_type}...")
            fw_result = dc_scm_checker.check_individual_firmware(fw_type, system_info['rscm_ip'], system_info['rscm_port'])
            
            # Safety check for None results
            if fw_result is None:
                fw_result = {
                    'version': 'METHOD_RETURNED_NONE',
                    'status': 'error',
                    'error': 'Firmware check method returned None',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'safety_fallback'
                }
            
            results['dc_scm']['firmware_versions'][fw_type] = fw_result
            results['progress']['completed'] += 1
            results['progress']['percentage'] = int((results['progress']['completed'] / total_fw_types) * 100)
            
            print(f"[THREAD {threading.current_thread().ident}] DC-SCM ({i}/{len(dc_scm_types_to_check)}): {fw_type} completed - {fw_result.get('status', 'unknown')} [Progress: {results['progress']['percentage']}%]")
            
            # Update progress in database
            with get_db_connection() as conn:
                conn.execute('''
                    UPDATE firmware_checks 
                    SET firmware_data = ?
                    WHERE id = ?
                ''', (json.dumps(results), check_id))
                conn.commit()
        
        results['dc_scm']['category'] = 'DC-SCM'
        results['dc_scm']['status'] = 'success'
        results['dc_scm']['timestamp'] = datetime.now().isoformat()
        
        # Check OVL2 firmware individually (SSH-heavy operations)
        with active_checks_lock:
            active_checks[check_id]['current_category'] = 'OVL2'
        
        # Determine which OVL2 firmware types to check (already calculated above)
        print(f"[THREAD {threading.current_thread().ident}] Checking OVL2 firmware ({len(ovl2_types_to_check)} types)...")
        
        # Use computer_name for MANA driver checks if provided
        computer_name = system_info.get('computer_name')
        
        for i, fw_type in enumerate(ovl2_types_to_check, 1):
            # Update progress
            results['progress']['current_category'] = 'OVL2'
            results['progress']['current_firmware'] = fw_type
            results['progress']['percentage'] = int((results['progress']['completed'] / total_fw_types) * 100)
            
            print(f"[THREAD {threading.current_thread().ident}] OVL2 ({i}/{len(ovl2_types_to_check)}): Checking {fw_type}...")
            fw_result = ovl2_checker.check_individual_firmware(fw_type, system_info['rscm_ip'], system_info['rscm_port'], computer_name=computer_name)
            
            # Safety check for None results
            if fw_result is None:
                fw_result = {
                    'version': 'METHOD_RETURNED_NONE',
                    'status': 'error',
                    'error': 'Firmware check method returned None',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'safety_fallback'
                }
            
            results['ovl2']['firmware_versions'][fw_type] = fw_result
            results['progress']['completed'] += 1
            results['progress']['percentage'] = int((results['progress']['completed'] / total_fw_types) * 100)
            
            print(f"[THREAD {threading.current_thread().ident}] OVL2 ({i}/{len(ovl2_types_to_check)}): {fw_type} completed - {fw_result.get('status', 'unknown')} [Progress: {results['progress']['percentage']}%]")
            
            # Update progress in database
            with get_db_connection() as conn:
                conn.execute('''
                    UPDATE firmware_checks 
                    SET firmware_data = ?
                    WHERE id = ?
                ''', (json.dumps(results), check_id))
                conn.commit()
        
        results['ovl2']['category'] = 'OVL2'
        results['ovl2']['status'] = 'success'
        results['ovl2']['timestamp'] = datetime.now().isoformat()
        
        # Check Other Platform firmware
        with active_checks_lock:
            active_checks[check_id]['current_category'] = 'Other Platform'
        
        # Use computer_name for storage checks if provided, otherwise use rscm_ip
        computer_name = system_info.get('computer_name', system_info['rscm_ip'])
        
        # Determine which Other Platform firmware types to check (already calculated above)
        if selected_firmware and 'other_platform' in selected_firmware:
            # Selective check - check individual firmware types
            print(f"[THREAD {threading.current_thread().ident}] Checking Other Platform firmware ({len(other_platform_types_to_check)} types)...")
            
            for i, fw_type in enumerate(other_platform_types_to_check, 1):
                # Update progress
                results['progress']['current_category'] = 'Other Platform'
                results['progress']['current_firmware'] = fw_type
                results['progress']['percentage'] = int((results['progress']['completed'] / total_fw_types) * 100)
                
                print(f"[THREAD {threading.current_thread().ident}] Other Platform ({i}/{len(other_platform_types_to_check)}): Checking {fw_type}...")
                fw_result = other_platform_checker.check_individual_firmware(fw_type, system_info['rscm_ip'], system_info['rscm_port'])
                
                # Safety check for None results
                if fw_result is None:
                    fw_result = {
                        'version': 'METHOD_RETURNED_NONE',
                        'status': 'error',
                        'error': 'Firmware check method returned None',
                        'checked_at': datetime.now().isoformat(),
                        'method': 'safety_fallback'
                    }
                
                results['other_platform']['firmware_versions'][fw_type] = fw_result
                results['progress']['completed'] += 1
                results['progress']['percentage'] = int((results['progress']['completed'] / total_fw_types) * 100)
                
                print(f"[THREAD {threading.current_thread().ident}] Other Platform ({i}/{len(other_platform_types_to_check)}): {fw_type} completed - {fw_result.get('status', 'unknown')} [Progress: {results['progress']['percentage']}%]")
                
                # Update progress in database
                with get_db_connection() as conn:
                    conn.execute('''
                        UPDATE firmware_checks 
                        SET firmware_data = ?
                        WHERE id = ?
                    ''', (json.dumps(results), check_id))
                    conn.commit()
        else:
            # Full check - use batch check for efficiency (update progress for each type as batch completes)
            print(f"[THREAD {threading.current_thread().ident}] Checking Other Platform firmware using batch check...")
            
            # Update progress to show we're starting Other Platform
            results['progress']['current_category'] = 'Other Platform'
            results['progress']['current_firmware'] = 'Batch check in progress...'
            
            other_results = other_platform_checker.check_all(
                rscm_ip=system_info['rscm_ip'], 
                system_port=system_info['rscm_port'],
                computer_name=computer_name
            )
            
            # Extract firmware versions from batch results
            if other_results and 'firmware_versions' in other_results:
                results['other_platform']['firmware_versions'].update(other_results['firmware_versions'])
                # Update progress for all types checked in batch
                results['progress']['completed'] += len(other_results['firmware_versions'])
                results['progress']['percentage'] = int((results['progress']['completed'] / total_fw_types) * 100)
                print(f"[THREAD {threading.current_thread().ident}] Other Platform check completed - {len(other_results['firmware_versions'])} firmware types checked [Progress: {results['progress']['percentage']}%]")
            else:
                # Fallback in case of batch check failure
                print(f"[THREAD {threading.current_thread().ident}] Other Platform batch check failed, using fallback values...")
                for fw_type in other_platform_checker.firmware_types:
                    results['other_platform']['firmware_versions'][fw_type] = {
                        'version': 'BATCH_CHECK_FAILED',
                        'status': 'error',
                        'error': 'Batch firmware check returned no results',
                        'checked_at': datetime.now().isoformat(),
                        'method': 'fallback'
                    }
                
                # Update progress in database
                with get_db_connection() as conn:
                    conn.execute('''
                        UPDATE firmware_checks 
                        SET firmware_data = ?
                        WHERE id = ?
                    ''', (json.dumps(results), check_id))
                    conn.commit()
        
        results['other_platform']['category'] = 'Other Platform'
        results['other_platform']['status'] = 'success' 
        results['other_platform']['timestamp'] = datetime.now().isoformat()
        
        # Mark progress as complete
        results['progress']['completed'] = total_fw_types
        results['progress']['percentage'] = 100
        results['progress']['current_category'] = 'Complete'
        results['progress']['current_firmware'] = 'All firmware checks completed'
        results['progress']['status'] = 'completed'
        
        end_time = time.time()
        duration = end_time - start_time
        print(f"[THREAD {threading.current_thread().ident}] All firmware checks completed for system: {system_info['name']} (Duration: {duration:.1f}s)")
        
        # Update the running check with final results
        with get_db_connection() as conn:
            conn.execute('''
                UPDATE firmware_checks 
                SET firmware_data = ?, status = ?
                WHERE id = ?
            ''', (json.dumps(results), 'success', check_id))
            conn.commit()
        
        # Remove from active checks
        with active_checks_lock:
            if check_id in active_checks:
                del active_checks[check_id]
        
        print(f"[THREAD {threading.current_thread().ident}] Firmware check completed successfully for Check ID: {check_id}")
        
    except Exception as e:
        logger.error(f"[THREAD {threading.current_thread().ident}] Error in threaded firmware check: {str(e)}")
        
        # Update the running check with error status
        try:
            with get_db_connection() as conn:
                conn.execute('''
                    UPDATE firmware_checks 
                    SET firmware_data = ?, status = ?, error_message = ?
                    WHERE id = ?
                ''', ('{}', 'error', str(e), check_id))
                conn.commit()
        except Exception as db_error:
            logger.error(f"[THREAD {threading.current_thread().ident}] Error updating database: {str(db_error)}")
        
        # Remove from active checks
        with active_checks_lock:
            if check_id in active_checks:
                active_checks[check_id]['status'] = 'error'
                active_checks[check_id]['error'] = str(e)

def compare_firmware_with_recipe(firmware_data, recipe_versions):
    """Compare actual firmware versions against recipe expectations"""
    comparison = {
        'total_checked': 0,
        'passed': 0,
        'failed': 0,
        'not_in_recipe': 0,
        'details': {}
    }
    
    # Iterate through each category in firmware data
    for category_key in ['dc_scm', 'other_platform', 'ovl2']:
        if category_key not in firmware_data:
            continue
            
        category_data = firmware_data[category_key]
        if not category_data or 'firmware_versions' not in category_data:
            continue
        
        category_name = category_data.get('category', category_key)
        comparison['details'][category_name] = {}
        
        # Get recipe expectations for this category
        recipe_category_versions = recipe_versions.get(category_name, {})
        
        # Compare each firmware type
        for fw_type, fw_info in category_data['firmware_versions'].items():
            actual_version = fw_info.get('version', 'N/A')
            expected_version = recipe_category_versions.get(fw_type)
            
            # Only compare if this firmware type is in the recipe
            if expected_version:
                comparison['total_checked'] += 1
                match = (actual_version == expected_version)
                
                if match:
                    comparison['passed'] += 1
                    status = 'pass'
                else:
                    comparison['failed'] += 1
                    status = 'fail'
                
                comparison['details'][category_name][fw_type] = {
                    'expected': expected_version,
                    'actual': actual_version,
                    'status': status
                }
            else:
                # Firmware type not in recipe
                comparison['not_in_recipe'] += 1
    
    return comparison

# Routes
@app.route('/')
def index():
    """Main dashboard page"""
    # Debug: Log SCRIPT_NAME for troubleshooting
    from flask import request as flask_request
    logger.info(f"[INDEX] SCRIPT_NAME: {flask_request.environ.get('SCRIPT_NAME', 'NOT SET')}")
    logger.info(f"[INDEX] url_for('systems'): {url_for('systems')}")
    
    with get_db_connection() as conn:
        # Get recent systems
        systems = conn.execute('''
            SELECT s.*, 
                   COUNT(fc.id) as check_count,
                   MAX(fc.check_date) as last_check
            FROM systems s
            LEFT JOIN firmware_checks fc ON s.id = fc.system_id
            GROUP BY s.id
            ORDER BY s.updated_at DESC
            LIMIT 10
        ''').fetchall()
        
        # Get recent firmware checks
        recent_checks = conn.execute('''
            SELECT fc.*, s.name as system_name
            FROM firmware_checks fc
            JOIN systems s ON fc.system_id = s.id
            ORDER BY fc.check_date DESC
            LIMIT 5
        ''').fetchall()
        
        stats = {
            'total_systems': conn.execute('SELECT COUNT(*) as count FROM systems').fetchone()['count'],
            'total_checks': conn.execute('SELECT COUNT(*) as count FROM firmware_checks').fetchone()['count'],
            'total_recipes': conn.execute('SELECT COUNT(*) as count FROM firmware_recipes').fetchone()['count'],
            'recent_systems': systems,
            'recent_checks': recent_checks
        }
    
    return render_template('index.html', stats=stats)

@app.route('/help')
def help():
    """Help and instructions page"""
    return render_template('help.html')

@app.route('/recipes')
def recipes():
    """List all firmware recipes"""
    with get_db_connection() as conn:
        recipes_rows = conn.execute('''
            SELECT r.*,
                   COUNT(fc.id) as usage_count
            FROM firmware_recipes r
            LEFT JOIN firmware_checks fc ON r.id = fc.recipe_id
            GROUP BY r.id
            ORDER BY r.name
        ''').fetchall()
    
    recipes_list = []
    for row in recipes_rows:
        recipe_dict = dict(row)
        # Parse firmware_versions JSON and count total versions
        try:
            firmware_versions = json.loads(recipe_dict['firmware_versions'])
            total_versions = sum(len(fws) for fws in firmware_versions.values())
            recipe_dict['total_versions'] = total_versions
        except:
            recipe_dict['total_versions'] = 0
        recipes_list.append(recipe_dict)
    
    return render_template('recipes.html', recipes=recipes_list)

@app.route('/recipes/add', methods=['GET', 'POST'])
def add_recipe():
    """Add a new firmware recipe"""
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        
        # Collect firmware versions from form
        firmware_versions = {}
        for key in request.form:
            if key.startswith('fw_'):
                # Parse fw_category_type format
                parts = key.split('_', 2)
                if len(parts) >= 3:
                    category = parts[1]
                    fw_type = '_'.join(parts[2:])
                    version = request.form[key].strip()
                    
                    if version:  # Only include if version is specified
                        if category not in firmware_versions:
                            firmware_versions[category] = {}
                        firmware_versions[category][fw_type] = version
        
        try:
            with get_db_connection() as conn:
                conn.execute('''
                    INSERT INTO firmware_recipes (name, description, firmware_versions)
                    VALUES (?, ?, ?)
                ''', (name, description, json.dumps(firmware_versions)))
                conn.commit()
            
            flash(f'Recipe "{name}" created successfully!', 'success')
            return redirect(url_for('recipes'))
            
        except sqlite3.IntegrityError:
            flash(f'Recipe name "{name}" already exists!', 'error')
        except Exception as e:
            flash(f'Error creating recipe: {str(e)}', 'error')
    
    # Get all firmware types for the form
    with get_db_connection() as conn:
        firmware_types = conn.execute('''
            SELECT category, name FROM firmware_types ORDER BY category, name
        ''').fetchall()
    
    # Group by category
    grouped_types = {}
    for ft in firmware_types:
        cat = ft['category']
        if cat not in grouped_types:
            grouped_types[cat] = []
        grouped_types[cat].append(ft['name'])
    
    return render_template('add_recipe.html', firmware_types=grouped_types)

@app.route('/recipes/<int:recipe_id>')
def recipe_detail(recipe_id):
    """View recipe details"""
    with get_db_connection() as conn:
        recipe = conn.execute('SELECT * FROM firmware_recipes WHERE id = ?', (recipe_id,)).fetchone()
        if not recipe:
            flash('Recipe not found!', 'error')
            return redirect(url_for('recipes'))
        
        # Get checks that used this recipe
        checks = conn.execute('''
            SELECT fc.*, s.name as system_name
            FROM firmware_checks fc
            JOIN systems s ON fc.system_id = s.id
            WHERE fc.recipe_id = ?
            ORDER BY fc.check_date DESC
            LIMIT 10
        ''', (recipe_id,)).fetchall()
    
    # Parse firmware versions
    firmware_versions = json.loads(recipe['firmware_versions'])
    
    return render_template('recipe_detail.html', recipe=recipe, 
                         firmware_versions=firmware_versions, checks=checks)

@app.route('/recipes/<int:recipe_id>/edit', methods=['GET', 'POST'])
def edit_recipe(recipe_id):
    """Edit an existing recipe"""
    with get_db_connection() as conn:
        recipe = conn.execute('SELECT * FROM firmware_recipes WHERE id = ?', (recipe_id,)).fetchone()
        if not recipe:
            flash('Recipe not found!', 'error')
            return redirect(url_for('recipes'))
    
    if request.method == 'POST':
        try:
            name = request.form.get('name', '').strip()
            description = request.form.get('description', '').strip()
            
            if not name:
                flash('Recipe name is required!', 'error')
                return redirect(url_for('edit_recipe', recipe_id=recipe_id))
            
            # Parse firmware versions from form data
            firmware_versions = {}
            for key, value in request.form.items():
                if key.startswith('fw_'):
                    # Format: fw_category_firmware_type
                    parts = key[3:].split('_', 1)
                    if len(parts) == 2:
                        category, fw_type = parts
                        # Replace underscores back with spaces for display
                        category = category.replace('_', ' ')
                        fw_type = fw_type.replace('_', ' ')
                        
                        if value.strip():  # Only add if version is not empty
                            if category not in firmware_versions:
                                firmware_versions[category] = {}
                            firmware_versions[category][fw_type] = value.strip()
            
            if not firmware_versions:
                flash('At least one firmware version must be specified!', 'error')
                return redirect(url_for('edit_recipe', recipe_id=recipe_id))
            
            # Update recipe in database
            with get_db_connection() as conn:
                conn.execute('''
                    UPDATE firmware_recipes 
                    SET name = ?, description = ?, firmware_versions = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (name, description, json.dumps(firmware_versions), recipe_id))
                conn.commit()
            
            flash(f'Recipe "{name}" has been updated successfully!', 'success')
            return redirect(url_for('recipe_detail', recipe_id=recipe_id))
            
        except Exception as e:
            flash(f'Error updating recipe: {str(e)}', 'error')
            return redirect(url_for('edit_recipe', recipe_id=recipe_id))
    
    # GET request - show edit form
    firmware_versions = json.loads(recipe['firmware_versions'])
    return render_template('edit_recipe.html', recipe=recipe, firmware_versions=firmware_versions)

@app.route('/recipes/<int:recipe_id>/delete', methods=['POST'])
def delete_recipe(recipe_id):
    """Delete a recipe"""
    try:
        with get_db_connection() as conn:
            recipe = conn.execute('SELECT name FROM firmware_recipes WHERE id = ?', (recipe_id,)).fetchone()
            if not recipe:
                flash('Recipe not found!', 'error')
                return redirect(url_for('recipes'))
            
            # Delete the recipe (checks will keep recipe_id but recipe will be gone)
            conn.execute('DELETE FROM firmware_recipes WHERE id = ?', (recipe_id,))
            conn.commit()
        
        flash(f'Recipe "{recipe["name"]}" has been deleted.', 'success')
        
    except Exception as e:
        flash(f'Error deleting recipe: {str(e)}', 'error')
    
    return redirect(url_for('recipes'))

@app.route('/systems')
def systems():
    """List all systems"""
    with get_db_connection() as conn:
        systems_rows = conn.execute('''
            SELECT s.*, 
                   COUNT(fc.id) as check_count,
                   MAX(fc.check_date) as last_check
            FROM systems s
            LEFT JOIN firmware_checks fc ON s.id = fc.system_id
            GROUP BY s.id
            ORDER BY s.name
        ''').fetchall()
    
    # Convert Row objects to dictionaries for JSON serialization
    systems_list = [dict(row) for row in systems_rows]
    
    return render_template('systems.html', systems=systems_list)

@app.route('/systems/add', methods=['GET', 'POST'])
def add_system():
    """Automated system registration"""
    if request.method == 'POST':
        try:
            # Get RSCM connection details
            rscm_ip = request.form['rscm_ip']
            system_port = request.form.get('system_port', 5, type=int)
            username = request.form.get('username', 'root')
            password = request.form['password']
            
            # Validate required fields
            if not rscm_ip or not password:
                flash('RSCM IP and password are required!', 'error')
                return render_template('add_system.html')
            
            # Try to connect and get serial number
            print(f"[AUTO-REG] Attempting to connect to {rscm_ip}:{system_port} with user '{username}'")
            dc_scm_checker = DCScmChecker(username=username, password=password, timeout=30)
            
            # Test connection first
            connection_test = dc_scm_checker.test_redfish_connection(rscm_ip, system_port)
            if connection_test['status'] != 'success':
                flash(f"Failed to connect to RSCM: {connection_test['message']}", 'error')
                return render_template('add_system.html')
            
            # Get system information including serial number
            print(f"[AUTO-REG] Connection successful, retrieving system information...")
            system_data = dc_scm_checker._get_redfish_data(rscm_ip, system_port, '/redfish/v1/System')
            
            if not system_data:
                flash('Failed to retrieve system information from RSCM', 'error')
                return render_template('add_system.html')
            
            # Extract serial number and system info
            serial_number = system_data.get('SerialNumber', 'Unknown')
            manufacturer = system_data.get('Manufacturer', 'Unknown')
            model = system_data.get('Model', 'Unknown')
            system_name = system_data.get('Name', 'Unknown')
            
            if serial_number == 'Unknown' or not serial_number:
                flash('Could not retrieve serial number from system', 'error')
                return render_template('add_system.html')
            
            print(f"[AUTO-REG] Retrieved Serial Number: {serial_number}")
            
            # Check if system already exists with this serial number
            with get_db_connection() as conn:
                existing = conn.execute(
                    'SELECT id FROM systems WHERE name = ?', 
                    (serial_number,)
                ).fetchone()
                
                if existing:
                    flash(f'System with serial number {serial_number} already exists!', 'warning')
                    return redirect(url_for('system_detail', system_id=existing['id']))
            
            # Store temporary data in session for metadata entry
            session['pending_system'] = {
                'serial_number': serial_number,
                'rscm_ip': rscm_ip,
                'system_port': system_port,
                'manufacturer': manufacturer,
                'model': model,
                'system_name': system_name
            }
            
            # Redirect to metadata entry page
            return redirect(url_for('add_system_metadata'))
            
        except Exception as e:
            logger.error(f"Error in automated system registration: {str(e)}")
            flash(f'Error during automated registration: {str(e)}', 'error')
            return render_template('add_system.html')
    
    return render_template('add_system.html')

@app.route('/systems/add-metadata', methods=['GET', 'POST'])
def add_system_metadata():
    """Add metadata to automatically discovered system"""
    # Check if we have pending system data
    if 'pending_system' not in session:
        flash('No pending system registration found. Please start the registration process.', 'warning')
        return redirect(url_for('add_system'))
    
    pending = session['pending_system']
    
    if request.method == 'POST':
        try:
            # Get metadata from form
            system_hostname = request.form.get('system_hostname', '')
            geo_location = request.form.get('geo_location', '')
            building = request.form.get('building', '')
            room = request.form.get('room', '')
            rack = request.form.get('rack', '')
            u_height = request.form.get('u_height', '')
            description = request.form.get('description', '')
            
            # Build description with hostname/IP and location metadata
            desc_parts = []
            if system_hostname:
                desc_parts.append(f"Host: {system_hostname}")
            if geo_location:
                desc_parts.append(f"Geo: {geo_location}")
            if building:
                desc_parts.append(f"Building: {building}")
            if room:
                desc_parts.append(f"Room: {room}")
            if rack:
                desc_parts.append(f"Rack: {rack}")
            if u_height:
                desc_parts.append(f"U: {u_height}")
            if description:
                desc_parts.append(description)
            
            full_description = " | ".join(desc_parts)
            
            # Create system record with serial number and metadata
            with get_db_connection() as conn:
                conn.execute('''
                    INSERT INTO systems (
                        name, rscm_ip, rscm_port, 
                        description
                    )
                    VALUES (?, ?, ?, ?)
                ''', (
                    pending['serial_number'],
                    pending['rscm_ip'],
                    pending['system_port'],
                    full_description
                ))
                conn.commit()
            
            # Clear session data
            session.pop('pending_system', None)
            
            flash(f'System {pending["serial_number"]} registered successfully with location metadata!', 'success')
            return redirect(url_for('systems'))
            
        except sqlite3.IntegrityError:
            flash(f'System with serial number {pending["serial_number"]} already exists!', 'error')
        except Exception as e:
            logger.error(f"Error saving system metadata: {str(e)}")
            flash(f'Error saving system: {str(e)}', 'error')
    
    return render_template('add_system_metadata.html', system=pending)

@app.route('/systems/<int:system_id>')
def system_detail(system_id):
    """Show system details and firmware checks"""
    with get_db_connection() as conn:
        system = conn.execute('SELECT * FROM systems WHERE id = ?', (system_id,)).fetchone()
        if not system:
            flash('System not found!', 'error')
            return redirect(url_for('systems'))
        
        checks = conn.execute('''
            SELECT * FROM firmware_checks 
            WHERE system_id = ? 
            ORDER BY check_date DESC
        ''', (system_id,)).fetchall()
        
        # Check for active/running firmware check
        active_check = conn.execute('''
            SELECT * FROM firmware_checks 
            WHERE system_id = ? AND status = 'running'
            ORDER BY check_date DESC 
            LIMIT 1
        ''', (system_id,)).fetchone()
        

    
    return render_template('system_detail.html', system=system, checks=checks, active_check=active_check)

@app.route('/systems/<int:system_id>/delete', methods=['POST'])
def delete_system(system_id):
    """Delete a system and all its firmware checks"""
    try:
        with get_db_connection() as conn:
            # First check if system exists
            system = conn.execute('SELECT name FROM systems WHERE id = ?', (system_id,)).fetchone()
            if not system:
                flash('System not found!', 'error')
                return redirect(url_for('systems'))
            
            # Delete firmware checks first (foreign key constraint)
            conn.execute('DELETE FROM firmware_checks WHERE system_id = ?', (system_id,))
            
            # Delete the system
            conn.execute('DELETE FROM systems WHERE id = ?', (system_id,))
            conn.commit()
        
        flash(f'System "{system["name"]}" and all its firmware checks have been deleted.', 'success')
        
    except Exception as e:
        flash(f'Error deleting system: {str(e)}', 'error')
    
    return redirect(url_for('systems'))

@app.route('/systems/<int:system_id>/edit', methods=['GET', 'POST'])
def edit_system(system_id):
    """Edit system information"""
    with get_db_connection() as conn:
        system = conn.execute('SELECT * FROM systems WHERE id = ?', (system_id,)).fetchone()
        if not system:
            flash('System not found!', 'error')
            return redirect(url_for('systems'))
    
    if request.method == 'POST':
        name = request.form['name']
        rscm_ip = request.form['rscm_ip']
        rscm_port = request.form.get('rscm_port', 22, type=int)
        
        # Get metadata from form
        system_hostname = request.form.get('system_hostname', '')
        geo_location = request.form.get('geo_location', '')
        building = request.form.get('building', '')
        room = request.form.get('room', '')
        rack = request.form.get('rack', '')
        u_height = request.form.get('u_height', '')
        additional_notes = request.form.get('additional_notes', '')
        
        # Build description with metadata
        desc_parts = []
        if system_hostname:
            desc_parts.append(f"Host: {system_hostname}")
        if geo_location:
            desc_parts.append(f"Geo: {geo_location}")
        if building:
            desc_parts.append(f"Building: {building}")
        if room:
            desc_parts.append(f"Room: {room}")
        if rack:
            desc_parts.append(f"Rack: {rack}")
        if u_height:
            desc_parts.append(f"U: {u_height}")
        if additional_notes:
            desc_parts.append(additional_notes)
        
        description = " | ".join(desc_parts)
        
        try:
            with get_db_connection() as conn:
                conn.execute('''
                    UPDATE systems 
                    SET name = ?, rscm_ip = ?, rscm_port = ?, description = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (name, rscm_ip, rscm_port, description, system_id))
                conn.commit()
            
            flash(f'System "{name}" updated successfully!', 'success')
            return redirect(url_for('system_detail', system_id=system_id))
            
        except sqlite3.IntegrityError:
            flash(f'System name "{name}" already exists!', 'error')
        except Exception as e:
            flash(f'Error updating system: {str(e)}', 'error')
    
    # Parse description into individual fields for GET request
    system_hostname = ''
    geo_location = ''
    building = ''
    room = ''
    rack = ''
    u_height = ''
    additional_notes = ''
    
    if system['description']:
        desc = system['description']
        # Parse structured metadata
        parts = desc.split('|')
        for part in parts:
            part = part.strip()
            if part.startswith('Host:'):
                system_hostname = part.replace('Host:', '').strip()
            elif part.startswith('Geo:'):
                geo_location = part.replace('Geo:', '').strip()
            elif part.startswith('Building:'):
                building = part.replace('Building:', '').strip()
            elif part.startswith('Room:'):
                room = part.replace('Room:', '').strip()
            elif part.startswith('Rack:'):
                rack = part.replace('Rack:', '').strip()
            elif part.startswith('U:'):
                u_height = part.replace('U:', '').strip()
            elif not any(part.startswith(prefix) for prefix in ['Host:', 'Geo:', 'Building:', 'Room:', 'Rack:', 'U:']):
                # This is additional notes (doesn't have a prefix)
                additional_notes = part
    
    return render_template('edit_system.html', 
                         system=system,
                         system_hostname=system_hostname,
                         geo_location=geo_location,
                         building=building,
                         room=room,
                         rack=rack,
                         u_height=u_height,
                         additional_notes=additional_notes)

@app.route('/check/<int:system_id>')
def check_firmware(system_id):
    """Check firmware versions for a system"""
    with get_db_connection() as conn:
        system = conn.execute('SELECT * FROM systems WHERE id = ?', (system_id,)).fetchone()
        if not system:
            flash('System not found!', 'error')
            return redirect(url_for('systems'))
        
        # Check for active/running firmware check
        active_check = conn.execute('''
            SELECT * FROM firmware_checks 
            WHERE system_id = ? AND status = 'running'
            ORDER BY check_date DESC 
            LIMIT 1
        ''', (system_id,)).fetchone()
    
    # Extract hostname from description if present
    system_hostname = None
    if system['description'] and 'Host:' in system['description']:
        # Extract hostname: "Host: <hostname> | ..." -> "<hostname>"
        try:
            host_part = system['description'].split('Host:')[1].split('|')[0].strip()
            system_hostname = host_part
        except (IndexError, AttributeError):
            system_hostname = None
    
    # Load available recipes for selection
    with get_db_connection() as conn:
        recipes = conn.execute('SELECT id, name FROM firmware_recipes ORDER BY name').fetchall()
    
    return render_template('check_firmware.html', system=system, active_check=active_check, 
                         system_hostname=system_hostname, recipes=recipes)

@app.route('/check/<int:system_id>/progress')
def check_progress(system_id):
    """View progress of an ongoing firmware check"""
    with get_db_connection() as conn:
        system = conn.execute('SELECT * FROM systems WHERE id = ?', (system_id,)).fetchone()
        if not system:
            flash('System not found!', 'error')
            return redirect(url_for('systems'))
        
        # Get the most recent check
        recent_check = conn.execute('''
            SELECT * FROM firmware_checks 
            WHERE system_id = ? 
            ORDER BY check_date DESC 
            LIMIT 1
        ''', (system_id,)).fetchone()
        
        # Parse firmware data if it exists
        parsed_firmware_data = None
        if recent_check and recent_check['firmware_data'] and recent_check['firmware_data'] != '{}':
            try:
                parsed_firmware_data = json.loads(recent_check['firmware_data'])
                print(f"[DEBUG] Successfully parsed firmware data with keys: {list(parsed_firmware_data.keys())}")
            except json.JSONDecodeError as e:
                print(f"[DEBUG] JSON decode error: {e}")
                print(f"[DEBUG] Raw firmware_data (first 200 chars): {recent_check['firmware_data'][:200]}")
                parsed_firmware_data = None
        else:
            print(f"[DEBUG] No firmware data to parse:")
            print(f"[DEBUG] - recent_check exists: {recent_check is not None}")
            if recent_check:
                print(f"[DEBUG] - firmware_data exists: {recent_check['firmware_data'] is not None}")
                print(f"[DEBUG] - firmware_data length: {len(recent_check['firmware_data']) if recent_check['firmware_data'] else 0}")
                print(f"[DEBUG] - firmware_data == '{{}}': {recent_check['firmware_data'] == '{}'}")
    
    print(f"[DEBUG] Final parsed_firmware_data is None: {parsed_firmware_data is None}")
    
    return render_template('check_progress.html', 
                         system=system, 
                         recent_check=recent_check,
                         firmware_data=parsed_firmware_data)

@app.route('/check/result/<int:check_id>')
def check_result(check_id):
    """View specific firmware check result"""
    with get_db_connection() as conn:
        # Get the specific check
        check = conn.execute('''
            SELECT fc.*, s.name as system_name, s.rscm_ip, s.rscm_port
            FROM firmware_checks fc
            JOIN systems s ON fc.system_id = s.id
            WHERE fc.id = ?
        ''', (check_id,)).fetchone()
        
        if not check:
            flash('Firmware check not found!', 'error')
            return redirect(url_for('index'))
        
        # Get recipe if one was used
        recipe = None
        recipe_versions = None
        if check['recipe_id']:
            recipe = conn.execute('SELECT * FROM firmware_recipes WHERE id = ?', 
                                 (check['recipe_id'],)).fetchone()
            if recipe:
                recipe_versions = json.loads(recipe['firmware_versions'])
        
        # Parse firmware data if it exists
        parsed_firmware_data = None
        print(f"[DEBUG] Check ID {check_id}: firmware_data exists: {bool(check['firmware_data'])}")
        print(f"[DEBUG] Check ID {check_id}: firmware_data length: {len(check['firmware_data']) if check['firmware_data'] else 0}")
        print(f"[DEBUG] Check ID {check_id}: firmware_data preview: {check['firmware_data'][:100] if check['firmware_data'] else 'None'}")
        
        if check['firmware_data'] and check['firmware_data'] != '{}':
            try:
                parsed_firmware_data = json.loads(check['firmware_data'])
                print(f"[DEBUG] Successfully parsed firmware data with keys: {list(parsed_firmware_data.keys())}")
                
                # If recipe exists, add comparison results
                if recipe_versions and parsed_firmware_data:
                    comparison_results = compare_firmware_with_recipe(parsed_firmware_data, recipe_versions)
                    parsed_firmware_data['recipe_comparison'] = comparison_results
                    
            except json.JSONDecodeError as e:
                print(f"[DEBUG] Error parsing firmware data: {e}")
                parsed_firmware_data = None
        else:
            print(f"[DEBUG] No firmware data to parse: {check['firmware_data']}")
        
        return render_template('check_result.html', 
                             check=check,
                             firmware_data=parsed_firmware_data,
                             recipe=recipe)

@app.route('/api/check/<int:check_id>/firmware-data')
def api_check_firmware_data(check_id):
    """API endpoint to get firmware data for a specific check"""
    with get_db_connection() as conn:
        check = conn.execute('''
            SELECT firmware_data, status
            FROM firmware_checks 
            WHERE id = ?
        ''', (check_id,)).fetchone()
        
        if not check:
            return jsonify({'error': 'Check not found'}), 404
        
        if not check['firmware_data'] or check['firmware_data'] == '{}':
            return jsonify({'error': 'No firmware data available'}), 404
            
        try:
            firmware_data = json.loads(check['firmware_data'])
            return jsonify(firmware_data)
        except json.JSONDecodeError:
            return jsonify({'error': 'Invalid firmware data'}), 500

@app.route('/api/check-status/<int:system_id>')
def api_check_status(system_id):
    """API endpoint to check status of running firmware check with threading info"""
    try:
        with get_db_connection() as conn:
            # Check for running check
            running_check = conn.execute('''
                SELECT * FROM firmware_checks 
                WHERE system_id = ? AND status = 'running'
                ORDER BY check_date DESC 
                LIMIT 1
            ''', (system_id,)).fetchone()
            
            if running_check:
                # Get thread information if available
                thread_info = None
                with active_checks_lock:
                    if running_check['id'] in active_checks:
                        info = active_checks[running_check['id']]
                        runtime = time.time() - info['start_time']
                        thread_info = {
                            'thread_id': info['thread_id'],
                            'runtime_seconds': runtime,
                            'runtime_minutes': runtime / 60,
                            'current_category': info.get('current_category', 'unknown'),
                            'thread_status': info.get('status', 'unknown')
                        }
                
                # Parse current firmware data to show progress
                progress_data = None
                if running_check['firmware_data'] and running_check['firmware_data'] != '{}':
                    try:
                        progress_data = json.loads(running_check['firmware_data'])
                    except json.JSONDecodeError:
                        pass
                
                return jsonify({
                    'status': 'running',
                    'check_id': running_check['id'],
                    'started': running_check['check_date'],
                    'thread_info': thread_info,
                    'progress_data': progress_data
                })
            
            # Check for most recent check (any status)
            recent_check = conn.execute('''
                SELECT * FROM firmware_checks 
                WHERE system_id = ?
                ORDER BY check_date DESC py 
                LIMIT 1
            ''', (system_id,)).fetchone()
            
            if recent_check:
                # Handle both 'success' (legacy) and 'completed' (new) status
                if recent_check['status'] in ('success', 'completed'):
                    return jsonify({
                        'status': 'completed',
                        'check_id': recent_check['id'],
                        'completed': recent_check['check_date'],
                        'error': None
                    })
                elif recent_check['status'] == 'error':
                    return jsonify({
                        'status': 'error',
                        'check_id': recent_check['id'],
                        'completed': recent_check['check_date'],
                        'error': recent_check.get('error_message')
                    })
                else:
                    # Status is something else (shouldn't happen, but handle gracefully)
                    return jsonify({
                        'status': recent_check['status'],
                        'check_id': recent_check['id'],
                        'completed': recent_check['check_date'],
                        'error': recent_check.get('error_message')
                    })
            
            return jsonify({'status': 'none'})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/check-firmware', methods=['POST'])
def api_check_firmware():
    """API endpoint to start firmware checks in background thread"""
    try:
        data = request.get_json()
        system_id = data.get('system_id')
        
        # Validate system exists
        with get_db_connection() as conn:
            system = conn.execute('SELECT * FROM systems WHERE id = ?', (system_id,)).fetchone()
            if not system:
                return jsonify({'error': 'System not found'}), 404
        
        # Check if there's already a running check for this system
        with get_db_connection() as conn:
            existing_check = conn.execute('''
                SELECT id FROM firmware_checks 
                WHERE system_id = ? AND status = 'running'
                ORDER BY check_date DESC 
                LIMIT 1
            ''', (system_id,)).fetchone()
            
            if existing_check:
                return jsonify({
                    'error': 'A firmware check is already running for this system',
                    'running_check_id': existing_check['id']
                }), 409
        
        # Get credentials from request data
        username = data.get('username', 'admin')
        password = data.get('password', 'admin')
        os_username = data.get('os_username')
        os_password = data.get('os_password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        # Get optional recipe_id
        recipe_id = data.get('recipe_id')
        if recipe_id:
            recipe_id = int(recipe_id) if recipe_id else None
        
        # Get optional selected firmware types
        selected_firmware = data.get('selected_firmware', None)
        if selected_firmware:
            print(f"[API] Selective check requested: {sum(len(v) for v in selected_firmware.values())} firmware types selected")
        else:
            print(f"[API] Full check requested: all firmware types will be checked")
        
        # Create initial "running" entry in database
        with get_db_connection() as conn:
            cursor = conn.execute('''
                INSERT INTO firmware_checks (system_id, firmware_data, status, recipe_id)
                VALUES (?, ?, ?, ?)
            ''', (system_id, '{"status": "initializing", "message": "Preparing firmware check..."}', 'running', recipe_id))
            check_id = cursor.lastrowid
            conn.commit()
        
        # Prepare system info for thread
        computer_name = data.get('computer_name')
        system_info = {
            'name': system['name'],
            'rscm_ip': system['rscm_ip'],
            'rscm_port': system['rscm_port'],
            'computer_name': computer_name
        }
        
        print(f"[API] Starting threaded firmware check for system: {system['name']} ({system['rscm_ip']}:{system['rscm_port']}) [Check ID: {check_id}]")
        
        # Submit firmware check to thread pool
        future = thread_pool.submit(
            perform_firmware_check_threaded, 
            check_id, 
            system_id, 
            system_info, 
            username, 
            password,
            os_username,
            os_password,
            selected_firmware
        )
        
        # Return immediately with check information
        return jsonify({
            'status': 'started',
            'check_id': check_id,
            'message': 'Firmware check started in background thread',
            'system_name': system['name'],
            'started_at': datetime.now().isoformat(),
            'progress_url': f'/check/{system_id}/progress',
            'check_url': f'/check/result/{check_id}'
        }), 202  # HTTP 202 Accepted
        
    except Exception as e:
        logger.error(f"Error starting firmware check: {str(e)}")
        
        # Update the running check with error status if check_id exists
        try:
            if 'check_id' in locals():
                with get_db_connection() as conn:
                    conn.execute('''
                        UPDATE firmware_checks 
                        SET firmware_data = ?, status = ?, error_message = ?
                        WHERE id = ?
                    ''', ('{}', 'error', f'Failed to start: {str(e)}', check_id))
                    conn.commit()
        except:
            pass
        
        return jsonify({'error': str(e)}), 500

@app.route('/api/check-firmware-individual', methods=['POST'])
def api_check_firmware_individual():
    """API endpoint to check individual firmware types
    
    This endpoint allows checking specific firmware types without running a full check.
    Useful for re-checking failed firmware or debugging specific types.
    
    Expected JSON body:
    {
        "check_id": 123,           # ID of the firmware check to update
        "firmware_type": "Cyclone V Image",
        "category": "ovl2",        # Category: dc_scm, ovl2, or other_platform
        "username": "admin",
        "password": "admin",
        "os_username": null,       # Optional for MANA driver
        "os_password": null,       # Optional for MANA driver
        "computer_name": null      # Optional for MANA driver
    }
    """
    try:
        data = request.get_json()
        check_id = data.get('check_id')
        firmware_type = data.get('firmware_type')
        category = data.get('category')
        
        if not all([check_id, firmware_type, category]):
            return jsonify({'error': 'check_id, firmware_type, and category are required'}), 400
        
        # Validate category
        valid_categories = ['dc_scm', 'ovl2', 'other_platform']
        if category not in valid_categories:
            return jsonify({'error': f'Invalid category. Must be one of: {", ".join(valid_categories)}'}), 400
        
        # Get the existing check record to get system info
        with get_db_connection() as conn:
            check = conn.execute('''
                SELECT fc.*, s.name as system_name, s.rscm_ip, s.rscm_port
                FROM firmware_checks fc
                JOIN systems s ON fc.system_id = s.id
                WHERE fc.id = ?
            ''', (check_id,)).fetchone()
            
            if not check:
                return jsonify({'error': 'Check not found'}), 404
        
        # Get credentials from request data
        username = data.get('username', 'admin')
        password = data.get('password', 'admin')
        os_username = data.get('os_username')
        os_password = data.get('os_password')
        computer_name = data.get('computer_name')
        
        logger.info(f"Checking individual firmware: {firmware_type} (category: {category}) for check ID: {check_id}")
        
        # Initialize the appropriate checker based on category
        result = None
        
        if category == 'dc_scm':
            dc_scm_checker = DCScmChecker(username=username, password=password)
            # DC-SCM uses check_individual_firmware method if it exists, otherwise use check_all
            if hasattr(dc_scm_checker, 'check_individual_firmware'):
                result = dc_scm_checker.check_individual_firmware(firmware_type, check['rscm_ip'], check['rscm_port'])
            else:
                # Fallback: run full check and extract the specific type
                full_results = dc_scm_checker.check_all(check['rscm_ip'], check['rscm_port'])
                if full_results and 'firmware_versions' in full_results:
                    result = full_results['firmware_versions'].get(firmware_type)
        
        elif category == 'ovl2':
            ovl2_checker = OVL2Checker(
                username=username, 
                password=password,
                os_username=os_username,
                os_password=os_password
            )
            result = ovl2_checker.check_individual_firmware(
                firmware_type, 
                check['rscm_ip'], 
                check['rscm_port'],
                computer_name=computer_name
            )
        
        elif category == 'other_platform':
            other_platform_checker = OtherPlatformChecker(
                username=username, 
                password=password,
                os_username=os_username,
                os_password=os_password
            )
            # Other Platform uses check_individual_firmware method if it exists
            if hasattr(other_platform_checker, 'check_individual_firmware'):
                result = other_platform_checker.check_individual_firmware(
                    firmware_type, 
                    check['rscm_ip'], 
                    check['rscm_port'],
                    computer_name=computer_name or check['rscm_ip']
                )
            else:
                # Fallback: run full check and extract the specific type
                full_results = other_platform_checker.check_all(
                    check['rscm_ip'], 
                    check['rscm_port'],
                    computer_name=computer_name or check['rscm_ip']
                )
                if full_results and 'firmware_versions' in full_results:
                    result = full_results['firmware_versions'].get(firmware_type)
        
        if result is None:
            return jsonify({
                'error': f'Failed to check firmware type: {firmware_type}',
                'status': 'error'
            }), 500
        
        # Update the existing check record with the new individual result
        with get_db_connection() as conn:
            # Get current firmware_data
            current_data = json.loads(check['firmware_data'] or '{}')
            
            # Update the specific firmware type in the appropriate category
            if category not in current_data:
                current_data[category] = {'firmware_versions': {}}
            if 'firmware_versions' not in current_data[category]:
                current_data[category]['firmware_versions'] = {}
            
            current_data[category]['firmware_versions'][firmware_type] = result
            
            # Save updated data
            conn.execute('''
                UPDATE firmware_checks 
                SET firmware_data = ?
                WHERE id = ?
            ''', (json.dumps(current_data), check_id))
            conn.commit()
        
        logger.info(f"Successfully updated individual firmware check: {firmware_type} -> {result.get('version', 'N/A')}")
        
        return jsonify({
            'status': 'success',
            'firmware_type': firmware_type,
            'category': category,
            'result': result,
            'updated_at': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error checking individual firmware: {str(e)}")
        return jsonify({'error': str(e), 'status': 'error'}), 500

@app.route('/firmware-types')
@app.route('/test-redfish')
def test_redfish():
    """Serve the Redfish connection test page"""
    import os
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_redfish.html')
    with open(test_file_path, 'r') as f:
        return f.read(), 200, {'Content-Type': 'text/html'}

@app.route('/api/test-connection', methods=['POST'])
def test_connection():
    """Test Redfish API connection to a system"""
    try:
        data = request.get_json()
        rscm_ip = data.get('rscm_ip')
        system_port = data.get('system_port', 5)  # Default to port 5 like your example
        username = data.get('username', 'admin')
        password = data.get('password', 'admin')
        
        if not rscm_ip:
            return jsonify({'error': 'RSCM IP is required'}), 400
        
        # Test connection with DC-SCM checker
        dc_scm_checker = DCScmChecker(username=username, password=password)
        
        # First test if Redfish is available
        connection_test = dc_scm_checker.test_redfish_connection(rscm_ip)
        
        if connection_test['status'] == 'success':
            # Try to get basic system information
            system_data = dc_scm_checker._get_redfish_data(rscm_ip, system_port, '/redfish/v1/System')
            
            if system_data:
                connection_info = {
                    'status': 'success',
                    'redfish_available': True,
                    'rack_manager_info': connection_test['rack_manager_info'],
                    'system_info': {
                        'id': system_data.get('Id', 'Unknown'),
                        'name': system_data.get('Name', 'Unknown'),
                        'manufacturer': system_data.get('Manufacturer', 'Unknown'),
                        'model': system_data.get('Model', 'Unknown'),
                        'serial_number': system_data.get('SerialNumber', 'Unknown'),
                        'bios_version': system_data.get('BiosVersion', 'Unknown'),
                        'power_state': system_data.get('PowerState', 'Unknown'),
                        'bmc_version': system_data.get('Oem', {}).get('Microsoft', {}).get('BMCVersion', 'Unknown'),
                        'cpld_version': system_data.get('Oem', {}).get('Microsoft', {}).get('DCSCMCPLDVersion', 'Unknown')
                    }
                }
                return jsonify(connection_info)
            else:
                return jsonify({
                    'status': 'partial_success',
                    'redfish_available': True,
                    'rack_manager_info': connection_test['rack_manager_info'],
                    'system_info': None,
                    'message': f'Redfish is available but system port {system_port} is not accessible'
                })
        else:
            return jsonify({
                'status': 'error',
                'redfish_available': False,
                'error': connection_test['message']
            }), 500
            
    except Exception as e:
        logger.error(f"Connection test failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/api/active-checks')
def api_active_checks():
    """API endpoint to get information about active threaded checks"""
    try:
        with active_checks_lock:
            active_info = {}
            for check_id, info in active_checks.items():
                runtime = time.time() - info['start_time']
                active_info[check_id] = {
                    'thread_id': info['thread_id'],
                    'runtime_seconds': runtime,
                    'runtime_minutes': runtime / 60,
                    'status': info['status'],
                    'current_category': info.get('current_category', 'unknown'),
                    'error': info.get('error')
                }
        
        # Also get database running checks for comparison
        with get_db_connection() as conn:
            db_running_checks = conn.execute('''
                SELECT id, system_id, check_date,
                       (julianday('now') - julianday(check_date)) * 24 * 60 as minutes_running
                FROM firmware_checks 
                WHERE status = 'running'
                ORDER BY check_date DESC
            ''').fetchall()
        
        db_info = []
        for check in db_running_checks:
            db_info.append({
                'check_id': check['id'],
                'system_id': check['system_id'],
                'minutes_running': check['minutes_running'],
                'in_active_threads': check['id'] in active_info
            })
        
        return jsonify({
            'active_threads': active_info,
            'thread_count': len(active_info),
            'database_running_checks': db_info,
            'database_count': len(db_info)
        })
        
    except Exception as e:
        logger.error(f"Error getting active checks: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/cleanup-orphaned-checks', methods=['POST'])
def api_cleanup_orphaned_checks():
    """API endpoint to manually cleanup orphaned running checks"""
    try:
        from datetime import datetime, timedelta
        
        # Allow specifying timeout threshold, default to 1 hour for manual cleanup
        data = request.get_json() or {}
        timeout_hours = data.get('timeout_hours', 1)
        
        timeout_threshold = datetime.now() - timedelta(hours=timeout_hours)
        
        with get_db_connection() as conn:
            # Find orphaned checks
            orphaned_checks = conn.execute('''
                SELECT id, system_id, check_date, 
                       (julianday('now') - julianday(check_date)) * 24 * 60 as minutes_running
                FROM firmware_checks 
                WHERE status = 'running' 
                AND check_date < ?
            ''', (timeout_threshold.isoformat(),)).fetchall()
            
            if orphaned_checks:
                check_ids = []
                for check in orphaned_checks:
                    check_ids.append(check['id'])
                    
                    # Update the orphaned check to 'error' status
                    conn.execute('''
                        UPDATE firmware_checks 
                        SET status = 'error', 
                            error_message = 'Check was manually reset (orphaned process cleanup)',
                            firmware_data = COALESCE(
                                NULLIF(firmware_data, '{"status": "initializing"}'),
                                '{"status": "manually_reset", "error": "Manually reset due to orphaned process"}'
                            )
                        WHERE id = ?
                    ''', (check['id'],))
                
                conn.commit()
                
                return jsonify({
                    'status': 'success',
                    'message': f'Cleaned up {len(orphaned_checks)} orphaned check(s)',
                    'cleaned_check_ids': check_ids,
                    'timeout_hours': timeout_hours
                })
            else:
                return jsonify({
                    'status': 'success', 
                    'message': 'No orphaned checks found',
                    'cleaned_check_ids': [],
                    'timeout_hours': timeout_hours
                })
                
    except Exception as e:
        logger.error(f"Error cleaning up orphaned checks: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

import atexit

def shutdown_thread_pool():
    """Shutdown thread pool gracefully"""
    print("Shutting down thread pool...")
    thread_pool.shutdown(wait=True)
    print("Thread pool shutdown complete.")

# Register shutdown handler
atexit.register(shutdown_thread_pool)

if __name__ == '__main__':
    print("=" * 80)
    print("FIRMWARE CHECKER WEB APPLICATION")
    print("=" * 80)
    print("Initializing database...")
    
    # Initialize database
    init_db()
    
    print("Database initialized successfully!")
    
    # Cleanup orphaned running checks on startup
    cleanup_orphaned_checks()
    
    print("Starting web server on http://0.0.0.0:5000")
    print("Access the application at: http://localhost:5000")
    print("=" * 80)
    print("Console output will show firmware check progress...")
    print("=" * 80)
    
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)