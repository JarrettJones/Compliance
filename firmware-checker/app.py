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
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3
import os
import sys
import signal
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
        # Programs table - Different programs that use firmware checking
        conn.execute('''
            CREATE TABLE IF NOT EXISTS programs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                check_methodology TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT valid_methodology CHECK (check_methodology IN ('echo_falls', 'standard', 'custom'))
            )
        ''')
        
        # Systems table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS systems (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                rscm_ip TEXT NOT NULL,
                rscm_port INTEGER NOT NULL DEFAULT 22,
                description TEXT,
                program_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(name, rscm_ip, rscm_port),
                FOREIGN KEY (program_id) REFERENCES programs (id)
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
        
        # Junction table for program-firmware type associations
        conn.execute('''
            CREATE TABLE IF NOT EXISTS program_firmware_types (
                program_id INTEGER NOT NULL,
                firmware_type_id INTEGER NOT NULL,
                PRIMARY KEY (program_id, firmware_type_id),
                FOREIGN KEY (program_id) REFERENCES programs (id) ON DELETE CASCADE,
                FOREIGN KEY (firmware_type_id) REFERENCES firmware_types (id) ON DELETE CASCADE
            )
        ''')
        
        # Firmware recipes table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS firmware_recipes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                firmware_versions TEXT NOT NULL,
                program_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(name, program_id),
                FOREIGN KEY (program_id) REFERENCES programs (id)
            )
        ''')
        
        # Users table for authentication
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'viewer',
                is_active INTEGER DEFAULT 1,
                email TEXT,
                first_name TEXT,
                last_name TEXT,
                team TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                CONSTRAINT valid_role CHECK (role IN ('admin', 'editor', 'viewer'))
            )
        ''')
        
        # Access requests table for user account requests
        conn.execute('''
            CREATE TABLE IF NOT EXISTS access_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                first_name TEXT NOT NULL,
                last_name TEXT,
                team TEXT,
                business_justification TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_by INTEGER,
                reviewed_at TIMESTAMP,
                notes TEXT,
                CONSTRAINT valid_status CHECK (status IN ('pending', 'approved', 'rejected')),
                FOREIGN KEY (reviewed_by) REFERENCES users (id)
            )
        ''')
        
        # Migrate existing users: Add new columns and migrate from is_admin
        try:
            # Check what columns exist
            cursor = conn.execute("PRAGMA table_info(users)")
            columns = [col[1] for col in cursor.fetchall()]
            
            # Add missing columns
            if 'role' not in columns:
                conn.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'viewer'")
                logger.info("Added role column to users table")
            
            if 'is_active' not in columns:
                conn.execute("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1")
                logger.info("Added is_active column to users table")
            
            if 'email' not in columns:
                conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
                logger.info("Added email column to users table")
            
            if 'first_name' not in columns:
                conn.execute("ALTER TABLE users ADD COLUMN first_name TEXT")
                logger.info("Added first_name column to users table")
            
            if 'last_name' not in columns:
                conn.execute("ALTER TABLE users ADD COLUMN last_name TEXT")
                logger.info("Added last_name column to users table")
            
            if 'team' not in columns:
                conn.execute("ALTER TABLE users ADD COLUMN team TEXT")
                logger.info("Added team column to users table")
            
            # Migrate data from is_admin to role
            if 'is_admin' in columns:
                conn.execute("""
                    UPDATE users 
                    SET role = CASE 
                        WHEN is_admin = 1 THEN 'admin'
                        ELSE 'editor'
                    END
                    WHERE role IS NULL OR role = '' OR role = 'viewer'
                """)
                conn.commit()
                logger.info("Migrated is_admin to role column")
        except Exception as e:
            logger.warning(f"Migration warning (may be safe to ignore): {e}")
        
        # Add recipe_id column to firmware_checks if it doesn't exist
        try:
            conn.execute('ALTER TABLE firmware_checks ADD COLUMN recipe_id INTEGER')
        except:
            pass  # Column already exists
        
        # Migrate systems table: Add program_id column
        try:
            cursor = conn.execute("PRAGMA table_info(systems)")
            system_columns = [col[1] for col in cursor.fetchall()]
            
            if 'program_id' not in system_columns:
                conn.execute("ALTER TABLE systems ADD COLUMN program_id INTEGER")
                logger.info("Added program_id column to systems table")
                
                # Create default Echo Falls program
                conn.execute("""
                    INSERT OR IGNORE INTO programs (name, description, check_methodology, is_active)
                    VALUES ('Echo Falls', 'Echo Falls datacenter program', 'echo_falls', 1)
                """)
                
                # Get the Echo Falls program ID
                echo_falls = conn.execute("SELECT id FROM programs WHERE name = 'Echo Falls'").fetchone()
                if echo_falls:
                    # Assign all existing systems to Echo Falls
                    conn.execute("""
                        UPDATE systems 
                        SET program_id = ?
                        WHERE program_id IS NULL
                    """, (echo_falls['id'],))
                    logger.info("Migrated existing systems to Echo Falls program")
                    
                    # Migrate recipes to Echo Falls program
                    conn.execute("""
                        UPDATE firmware_recipes 
                        SET program_id = ?
                        WHERE program_id IS NULL
                    """, (echo_falls['id'],))
                    logger.info("Migrated existing recipes to Echo Falls program")
        except Exception as e:
            logger.warning(f"Program migration warning (may be safe to ignore): {e}")
        
        # Add program_id column to firmware_recipes if it doesn't exist
        try:
            cursor = conn.execute("PRAGMA table_info(firmware_recipes)")
            recipe_columns = [col[1] for col in cursor.fetchall()]
            
            if 'program_id' not in recipe_columns:
                conn.execute("ALTER TABLE firmware_recipes ADD COLUMN program_id INTEGER")
                logger.info("Added program_id column to firmware_recipes table")
                
                # Assign existing recipes to Echo Falls
                echo_falls = conn.execute("SELECT id FROM programs WHERE name = 'Echo Falls'").fetchone()
                if echo_falls:
                    conn.execute("""
                        UPDATE firmware_recipes 
                        SET program_id = ?
                        WHERE program_id IS NULL
                    """, (echo_falls['id'],))
        except Exception as e:
            logger.warning(f"Recipe migration warning (may be safe to ignore): {e}")
        
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

def create_default_admin():
    """Create default admin user if no users exist"""
    with get_db_connection() as conn:
        user_count = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
        
        if user_count == 0:
            # Create default admin user: username = admin, password = admin
            default_username = 'admin'
            default_password = 'admin'
            password_hash = generate_password_hash(default_password)
            
            conn.execute('''
                INSERT INTO users (username, password_hash, is_admin)
                VALUES (?, ?, 1)
            ''', (default_username, password_hash))
            conn.commit()
            
            print("=" * 80)
            print("DEFAULT ADMIN USER CREATED")
            print("=" * 80)
            print(f"Username: {default_username}")
            print(f"Password: {default_password}")
            print("=" * 80)
            print("IMPORTANT: Please change the default password after first login!")
            print("=" * 80)

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        if session.get('role') != 'admin':
            flash('You need administrator privileges to access this page.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def editor_required(f):
    """Decorator to require editor or admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        if session.get('role') not in ['admin', 'editor']:
            flash('You need editor privileges to perform this action.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

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
            'check_id': check_id,
            'check_date': datetime.now().isoformat(),
            'system_details': {
                'system_id': system_id,
                'serial_number': system_info['name'],
                'system_name': system_info['name'],  # Serial number (kept for backward compatibility)
                'rscm_ip': system_info['rscm_ip'],
                'rscm_port': system_info['rscm_port'],
                'computer_name': system_info.get('computer_name'),  # Hostname/IP for WinRM
                'hostname': system_info.get('computer_name')  # Alias for clarity
            },
            # Legacy fields (kept for backward compatibility)
            'system_id': system_id,
            'system_name': system_info['name'],
            'rscm_ip': system_info['rscm_ip'],
            'rscm_port': system_info['rscm_port'],
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
                fw_result = other_platform_checker.check_individual_firmware(fw_type, system_info['rscm_ip'], system_info['rscm_port'], computer_name=computer_name)
                
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

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        with get_db_connection() as conn:
            user = conn.execute(
                'SELECT * FROM users WHERE username = ?',
                (username,)
            ).fetchone()
            
            if user and check_password_hash(user['password_hash'], password):
                # Check if user is active
                try:
                    is_active = user['is_active']
                except (KeyError, IndexError):
                    is_active = 1  # Default to active for backwards compatibility
                
                if not is_active:
                    flash('Your account has been deactivated. Please contact an administrator.', 'error')
                    return render_template('login.html')
                
                # Login successful
                session['user_id'] = user['id']
                session['username'] = user['username']
                
                # Set role - migrate from is_admin if role doesn't exist
                try:
                    role = user['role']
                except (KeyError, IndexError):
                    # Fallback to is_admin for migration
                    try:
                        role = 'admin' if user['is_admin'] else 'editor'
                    except (KeyError, IndexError):
                        role = 'viewer'
                
                session['role'] = role
                session['is_admin'] = 1 if role == 'admin' else 0  # Keep for backwards compatibility
                
                # Update last login time
                conn.execute(
                    'UPDATE users SET last_login = ? WHERE id = ?',
                    (datetime.now().isoformat(), user['id'])
                )
                conn.commit()
                
                flash(f'Welcome back, {username}!', 'success')
                
                # Redirect to next page or admin panel
                next_page = request.args.get('next')
                return redirect(next_page if next_page else url_for('admin'))
            else:
                flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout user"""
    username = session.get('username', 'User')
    session.clear()
    flash(f'Goodbye, {username}!', 'info')
    return redirect(url_for('index'))

# Access Request Routes
@app.route('/request-access', methods=['GET', 'POST'])
def request_access():
    """Request access to the application"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        team = request.form.get('team', '').strip()
        business_justification = request.form.get('business_justification', '').strip()
        
        if not email or not first_name or not business_justification:
            flash('Email, first name, and business justification are required', 'error')
            return redirect(url_for('request_access'))
        
        # Check if email already has a pending request
        with get_db_connection() as conn:
            existing_request = conn.execute(
                "SELECT * FROM access_requests WHERE email = ? AND status = 'pending'",
                (email,)
            ).fetchone()
            
            if existing_request:
                flash('You already have a pending access request. Please wait for admin approval.', 'warning')
                return redirect(url_for('login'))
            
            # Check if user already exists
            existing_user = conn.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()
            
            if existing_user:
                flash('An account with this email already exists. Please try logging in.', 'warning')
                return redirect(url_for('login'))
            
            # Create access request
            conn.execute('''
                INSERT INTO access_requests (email, first_name, last_name, team, business_justification)
                VALUES (?, ?, ?, ?, ?)
            ''', (email, first_name, last_name, team, business_justification))
            conn.commit()
        
        flash('Access request submitted successfully! An administrator will review your request.', 'success')
        return redirect(url_for('login'))
    
    return render_template('request_access.html')

@app.route('/admin/access-requests')
@admin_required
def admin_access_requests():
    """View all access requests"""
    status_filter = request.args.get('status', 'pending')
    
    with get_db_connection() as conn:
        if status_filter == 'all':
            requests_list = conn.execute('''
                SELECT ar.*, u.username as reviewed_by_username
                FROM access_requests ar
                LEFT JOIN users u ON ar.reviewed_by = u.id
                ORDER BY ar.requested_at DESC
            ''').fetchall()
        else:
            requests_list = conn.execute('''
                SELECT ar.*, u.username as reviewed_by_username
                FROM access_requests ar
                LEFT JOIN users u ON ar.reviewed_by = u.id
                WHERE ar.status = ?
                ORDER BY ar.requested_at DESC
            ''', (status_filter,)).fetchall()
        
        # Count by status
        status_counts = {
            'pending': conn.execute("SELECT COUNT(*) as count FROM access_requests WHERE status = 'pending'").fetchone()['count'],
            'approved': conn.execute("SELECT COUNT(*) as count FROM access_requests WHERE status = 'approved'").fetchone()['count'],
            'rejected': conn.execute("SELECT COUNT(*) as count FROM access_requests WHERE status = 'rejected'").fetchone()['count'],
            'all': conn.execute('SELECT COUNT(*) as count FROM access_requests').fetchone()['count']
        }
    
    return render_template('admin_access_requests.html', 
                         requests=requests_list, 
                         status_counts=status_counts,
                         status_filter=status_filter)

@app.route('/admin/access-requests/<int:request_id>/approve', methods=['POST'])
@admin_required
def approve_access_request(request_id):
    """Approve an access request and create user account"""
    with get_db_connection() as conn:
        access_request = conn.execute(
            'SELECT * FROM access_requests WHERE id = ?',
            (request_id,)
        ).fetchone()
        
        if not access_request:
            flash('Access request not found', 'error')
            return redirect(url_for('admin_access_requests'))
        
        if access_request['status'] != 'pending':
            flash('This request has already been processed', 'warning')
            return redirect(url_for('admin_access_requests'))
        
        # Generate username from email
        username = access_request['email'].split('@')[0]
        
        # Check if username exists, append number if needed
        base_username = username
        counter = 1
        while conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone():
            username = f"{base_username}{counter}"
            counter += 1
        
        # Generate temporary password
        import secrets
        temp_password = secrets.token_urlsafe(12)
        password_hash = generate_password_hash(temp_password)
        
        # Get requested role from form, default to viewer
        role = request.form.get('role', 'viewer')
        if role not in ['admin', 'editor', 'viewer']:
            role = 'viewer'
        
        try:
            # Create user account
            conn.execute('''
                INSERT INTO users (username, password_hash, role, email, first_name, last_name, team)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (username, password_hash, role, access_request['email'], 
                  access_request['first_name'], access_request['last_name'], 
                  access_request['team']))
            
            # Update access request status
            conn.execute('''
                UPDATE access_requests
                SET status = 'approved', reviewed_by = ?, reviewed_at = ?, 
                    notes = ?
                WHERE id = ?
            ''', (session['user_id'], datetime.now().isoformat(), 
                  f'User account created: {username}', request_id))
            
            conn.commit()
            
            flash(f'Access request approved! User account created: {username} | Temporary password: {temp_password}', 'success')
            flash('Please share the temporary password with the user securely.', 'info')
            
        except Exception as e:
            flash(f'Error creating user account: {str(e)}', 'error')
    
    return redirect(url_for('admin_access_requests'))

@app.route('/admin/access-requests/<int:request_id>/reject', methods=['POST'])
@admin_required
def reject_access_request(request_id):
    """Reject an access request"""
    notes = request.form.get('notes', '')
    
    with get_db_connection() as conn:
        access_request = conn.execute(
            'SELECT * FROM access_requests WHERE id = ?',
            (request_id,)
        ).fetchone()
        
        if not access_request:
            flash('Access request not found', 'error')
            return redirect(url_for('admin_access_requests'))
        
        if access_request['status'] != 'pending':
            flash('This request has already been processed', 'warning')
            return redirect(url_for('admin_access_requests'))
        
        # Update access request status
        conn.execute('''
            UPDATE access_requests
            SET status = 'rejected', reviewed_by = ?, reviewed_at = ?, notes = ?
            WHERE id = ?
        ''', (session['user_id'], datetime.now().isoformat(), notes, request_id))
        conn.commit()
        
        flash('Access request rejected', 'info')
    
    return redirect(url_for('admin_access_requests'))

# Program Management Routes
@app.route('/admin/programs')
@admin_required
def admin_programs():
    """Program management page"""
    with get_db_connection() as conn:
        programs = conn.execute('''
            SELECT p.*,
                   COUNT(DISTINCT s.id) as system_count,
                   COUNT(DISTINCT fc.id) as check_count,
                   COUNT(DISTINCT fr.id) as recipe_count
            FROM programs p
            LEFT JOIN systems s ON p.id = s.program_id
            LEFT JOIN firmware_checks fc ON s.id = fc.system_id
            LEFT JOIN firmware_recipes fr ON p.id = fr.program_id
            GROUP BY p.id
            ORDER BY p.is_active DESC, p.name
        ''').fetchall()
    
    return render_template('admin_programs.html', programs=programs)

@app.route('/admin/programs/add', methods=['GET', 'POST'])
@admin_required
def admin_add_program():
    """Add a new program"""
    with get_db_connection() as conn:
        if request.method == 'POST':
            name = request.form.get('name', '').strip()
            description = request.form.get('description', '').strip()
            check_methodology = request.form.get('check_methodology', 'standard')
            is_active = 1 if request.form.get('is_active') == 'on' else 0
            firmware_type_ids = request.form.getlist('firmware_types')  # Get selected firmware types
            
            if not name:
                flash('Program name is required', 'error')
                return redirect(url_for('admin_add_program'))
            
            if check_methodology not in ['echo_falls', 'standard', 'custom']:
                flash('Invalid check methodology', 'error')
                return redirect(url_for('admin_add_program'))
            
            try:
                # Insert program
                cursor = conn.execute('''
                    INSERT INTO programs (name, description, check_methodology, is_active)
                    VALUES (?, ?, ?, ?)
                ''', (name, description, check_methodology, is_active))
                program_id = cursor.lastrowid
                
                # Associate firmware types with the program
                for firmware_type_id in firmware_type_ids:
                    conn.execute('''
                        INSERT INTO program_firmware_types (program_id, firmware_type_id)
                        VALUES (?, ?)
                    ''', (program_id, int(firmware_type_id)))
                
                conn.commit()
                
                flash(f'Program "{name}" created successfully with {len(firmware_type_ids)} firmware type(s)', 'success')
                return redirect(url_for('admin_programs'))
            
            except sqlite3.IntegrityError:
                flash(f'A program with the name "{name}" already exists', 'error')
                return redirect(url_for('admin_add_program'))
        
        # GET request - show form with all firmware types
        firmware_types = conn.execute('''
            SELECT * FROM firmware_types ORDER BY category, name
        ''').fetchall()
        
        # Group firmware types by category
        firmware_by_category = {}
        for ft in firmware_types:
            if ft['category'] not in firmware_by_category:
                firmware_by_category[ft['category']] = []
            firmware_by_category[ft['category']].append(ft)
        
        return render_template('admin_program_form.html', 
                             program=None, 
                             action='Add',
                             firmware_by_category=firmware_by_category,
                             selected_firmware_types=[])

@app.route('/admin/programs/edit/<int:program_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_program(program_id):
    """Edit an existing program"""
    with get_db_connection() as conn:
        program = conn.execute('SELECT * FROM programs WHERE id = ?', (program_id,)).fetchone()
        
        if not program:
            flash('Program not found', 'error')
            return redirect(url_for('admin_programs'))
        
        if request.method == 'POST':
            name = request.form.get('name', '').strip()
            description = request.form.get('description', '').strip()
            check_methodology = request.form.get('check_methodology', 'standard')
            is_active = 1 if request.form.get('is_active') == 'on' else 0
            firmware_type_ids = request.form.getlist('firmware_types')  # Get selected firmware types
            
            if not name:
                flash('Program name is required', 'error')
                return render_template('admin_program_form.html', program=program, action='Edit')
            
            if check_methodology not in ['echo_falls', 'standard', 'custom']:
                flash('Invalid check methodology', 'error')
                return render_template('admin_program_form.html', program=program, action='Edit')
            
            try:
                # Update program
                conn.execute('''
                    UPDATE programs
                    SET name = ?, description = ?, check_methodology = ?, 
                        is_active = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (name, description, check_methodology, is_active, program_id))
                
                # Update firmware type associations - delete old ones and add new ones
                conn.execute('DELETE FROM program_firmware_types WHERE program_id = ?', (program_id,))
                for firmware_type_id in firmware_type_ids:
                    conn.execute('''
                        INSERT INTO program_firmware_types (program_id, firmware_type_id)
                        VALUES (?, ?)
                    ''', (program_id, int(firmware_type_id)))
                
                conn.commit()
                
                flash(f'Program "{name}" updated successfully', 'success')
                return redirect(url_for('admin_programs'))
            
            except sqlite3.IntegrityError:
                flash(f'A program with the name "{name}" already exists', 'error')
                return render_template('admin_program_form.html', program=program, action='Edit')
        
        # GET request - show form with all firmware types and current selections
        firmware_types = conn.execute('''
            SELECT * FROM firmware_types ORDER BY category, name
        ''').fetchall()
        
        # Group firmware types by category
        firmware_by_category = {}
        for ft in firmware_types:
            if ft['category'] not in firmware_by_category:
                firmware_by_category[ft['category']] = []
            firmware_by_category[ft['category']].append(ft)
        
        # Get currently selected firmware types for this program
        selected_firmware_types = [
            row['firmware_type_id'] for row in conn.execute('''
                SELECT firmware_type_id FROM program_firmware_types WHERE program_id = ?
            ''', (program_id,)).fetchall()
        ]
        
        return render_template('admin_program_form.html', 
                             program=program, 
                             action='Edit',
                             firmware_by_category=firmware_by_category,
                             selected_firmware_types=selected_firmware_types)

@app.route('/admin/programs/toggle/<int:program_id>', methods=['POST'])
@admin_required
def admin_toggle_program(program_id):
    """Toggle program active status"""
    with get_db_connection() as conn:
        program = conn.execute('SELECT * FROM programs WHERE id = ?', (program_id,)).fetchone()
        
        if not program:
            flash('Program not found', 'error')
            return redirect(url_for('admin_programs'))
        
        new_status = 0 if program['is_active'] else 1
        conn.execute('''
            UPDATE programs
            SET is_active = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (new_status, program_id))
        conn.commit()
        
        status_text = 'activated' if new_status else 'deactivated'
        flash(f'Program "{program["name"]}" has been {status_text}', 'success')
    
    return redirect(url_for('admin_programs'))

# Routes
@app.route('/select-program')
@login_required
def select_program():
    """Program selection page - shows tiles of available programs"""
    with get_db_connection() as conn:
        programs = conn.execute('''
            SELECT p.*,
                   COUNT(DISTINCT s.id) as system_count,
                   COUNT(DISTINCT fc.id) as check_count
            FROM programs p
            LEFT JOIN systems s ON p.id = s.program_id
            LEFT JOIN firmware_checks fc ON s.id = fc.system_id
            WHERE p.is_active = 1
            GROUP BY p.id
            ORDER BY p.name
        ''').fetchall()
    
    return render_template('select_program.html', programs=programs)

@app.route('/set-program/<int:program_id>')
@login_required
def set_program(program_id):
    """Set the active program for the user session"""
    with get_db_connection() as conn:
        program = conn.execute('''
            SELECT * FROM programs WHERE id = ? AND is_active = 1
        ''', (program_id,)).fetchone()
        
        if not program:
            flash('Invalid program selected', 'error')
            return redirect(url_for('select_program'))
        
        session['program_id'] = program_id
        session['program_name'] = program['name']
        flash(f'Now working with {program["name"]}', 'success')
    
    return redirect(url_for('index'))

@app.route('/')
def index():
    """Main dashboard page"""
    # If user is logged in but hasn't selected a program, redirect to program selector
    if 'user_id' in session and 'program_id' not in session:
        return redirect(url_for('select_program'))
    
    # Debug: Log SCRIPT_NAME for troubleshooting
    from flask import request as flask_request
    logger.info(f"[INDEX] SCRIPT_NAME: {flask_request.environ.get('SCRIPT_NAME', 'NOT SET')}")
    logger.info(f"[INDEX] url_for('systems'): {url_for('systems')}")
    
    with get_db_connection() as conn:
        program_id = session.get('program_id')
        
        # Build query filters based on selected program
        program_filter = ''
        program_params = []
        if program_id:
            program_filter = 'WHERE s.program_id = ?'
            program_params = [program_id]
        
        # Get recent systems for this program
        systems = conn.execute(f'''
            SELECT s.*, 
                   COUNT(fc.id) as check_count,
                   MAX(fc.check_date) as last_check
            FROM systems s
            LEFT JOIN firmware_checks fc ON s.id = fc.system_id
            {program_filter}
            GROUP BY s.id
            ORDER BY s.updated_at DESC
            LIMIT 5
        ''', program_params).fetchall()
        
        # Get recent firmware checks for this program
        recent_checks = conn.execute(f'''
            SELECT fc.*, s.name as system_name
            FROM firmware_checks fc
            JOIN systems s ON fc.system_id = s.id
            {program_filter}
            ORDER BY fc.check_date DESC
            LIMIT 5
        ''', program_params).fetchall()
        
        # Get stats for this program
        # Count firmware types assigned to this program
        if program_id:
            firmware_types_count = conn.execute('''
                SELECT COUNT(*) as count 
                FROM program_firmware_types 
                WHERE program_id = ?
            ''', (program_id,)).fetchone()['count']
            
            # Get firmware types grouped by category for this program
            firmware_types = conn.execute('''
                SELECT ft.category, COUNT(ft.id) as count
                FROM firmware_types ft
                INNER JOIN program_firmware_types pft ON ft.id = pft.firmware_type_id
                WHERE pft.program_id = ?
                GROUP BY ft.category
                ORDER BY ft.category
            ''', (program_id,)).fetchall()
        else:
            firmware_types_count = conn.execute('SELECT COUNT(*) as count FROM firmware_types').fetchone()['count']
            
            # Get all firmware types grouped by category
            firmware_types = conn.execute('''
                SELECT category, COUNT(id) as count
                FROM firmware_types
                GROUP BY category
                ORDER BY category
            ''').fetchall()
        
        # Convert to dict for easier template access
        firmware_by_category = {row['category']: row['count'] for row in firmware_types}
        
        stats = {
            'total_systems': conn.execute(f'SELECT COUNT(*) as count FROM systems s {program_filter}', program_params).fetchone()['count'],
            'total_checks': conn.execute(f'''
                SELECT COUNT(*) as count 
                FROM firmware_checks fc
                JOIN systems s ON fc.system_id = s.id
                {program_filter}
            ''', program_params).fetchone()['count'],
            'total_recipes': conn.execute(f'SELECT COUNT(*) as count FROM firmware_recipes fr {program_filter.replace("s.program_id", "fr.program_id")}', program_params).fetchone()['count'],
            'total_firmware_types': firmware_types_count,
            'recent_systems': systems,
            'recent_checks': recent_checks
        }
    
    return render_template('index.html', stats=stats, firmware_by_category=firmware_by_category)

@app.route('/help')
def help():
    """Help and instructions page"""
    return render_template('help.html')

@app.route('/admin')
@admin_required
def admin():
    """Admin panel for application management"""
    # Get app statistics
    with get_db_connection() as conn:
        stats = {
            'total_systems': conn.execute('SELECT COUNT(*) as count FROM systems').fetchone()['count'],
            'total_checks': conn.execute('SELECT COUNT(*) as count FROM firmware_checks').fetchone()['count'],
            'total_recipes': conn.execute('SELECT COUNT(*) as count FROM firmware_recipes').fetchone()['count'],
            'running_checks': conn.execute("SELECT COUNT(*) as count FROM firmware_checks WHERE status = 'running'").fetchone()['count']
        }
        
        # Get running checks details
        running_checks = conn.execute('''
            SELECT fc.id, fc.check_date, s.name as system_name, s.rscm_ip,
                   (julianday('now') - julianday(fc.check_date)) * 24 * 60 as minutes_running
            FROM firmware_checks fc
            JOIN systems s ON fc.system_id = s.id
            WHERE fc.status = 'running'
            ORDER BY fc.check_date DESC
        ''').fetchall()
        
        # Get pending access requests count
        pending_requests = conn.execute(
            "SELECT COUNT(*) as count FROM access_requests WHERE status = 'pending'"
        ).fetchone()['count']
    
    # Get version information
    import flask
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    flask_version = flask.__version__
    
    return render_template('admin.html', 
                         stats=stats, 
                         running_checks=running_checks,
                         python_version=python_version,
                         flask_version=flask_version,
                         pending_requests=pending_requests)

# User Management Routes
@app.route('/admin/users')
@admin_required
def admin_users():
    """User management page"""
    team_filter = request.args.get('team', 'all')
    
    with get_db_connection() as conn:
        # Get all users
        if team_filter == 'all':
            users = conn.execute('''
                SELECT id, username, role, is_active, email, first_name, last_name, team,
                       created_at, last_login
                FROM users
                ORDER BY role, username
            ''').fetchall()
        else:
            users = conn.execute('''
                SELECT id, username, role, is_active, email, first_name, last_name, team,
                       created_at, last_login
                FROM users
                WHERE team = ?
                ORDER BY role, username
            ''', (team_filter,)).fetchall()
        
        # Count users by team
        team_counts = {
            'all': conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count'],
            'SIT': conn.execute("SELECT COUNT(*) as count FROM users WHERE team = 'SIT'").fetchone()['count'],
            'SLGS': conn.execute("SELECT COUNT(*) as count FROM users WHERE team = 'SLGS'").fetchone()['count'],
            'Other': conn.execute("SELECT COUNT(*) as count FROM users WHERE team = 'Other' OR team IS NULL OR team = ''").fetchone()['count']
        }
    
    return render_template('admin_users.html', users=users, team_counts=team_counts, team_filter=team_filter)

@app.route('/admin/users/add', methods=['GET', 'POST'])
@admin_required
def admin_add_user():
    """Add a new user"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'viewer')
        email = request.form.get('email', '')
        first_name = request.form.get('first_name', '')
        last_name = request.form.get('last_name', '')
        team = request.form.get('team', '')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return redirect(url_for('admin_add_user'))
        
        if role not in ['admin', 'editor', 'viewer']:
            flash('Invalid role', 'error')
            return redirect(url_for('admin_add_user'))
        
        password_hash = generate_password_hash(password)
        
        try:
            with get_db_connection() as conn:
                conn.execute('''
                    INSERT INTO users (username, password_hash, role, email, first_name, last_name, team)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (username, password_hash, role, email, first_name, last_name, team))
                conn.commit()
            
            flash(f'User "{username}" created successfully with {role} role!', 'success')
            return redirect(url_for('admin_users'))
            
        except sqlite3.IntegrityError:
            flash(f'Username "{username}" already exists!', 'error')
        except Exception as e:
            flash(f'Error creating user: {str(e)}', 'error')
    
    return render_template('register.html', is_admin_adding=True)

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    """Edit user details"""
    with get_db_connection() as conn:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('admin_users'))
        
        if request.method == 'POST':
            role = request.form.get('role', user['role'])
            email = request.form.get('email', '')
            first_name = request.form.get('first_name', '')
            last_name = request.form.get('last_name', '')
            team = request.form.get('team', '')
            new_password = request.form.get('new_password', '')
            
            if role not in ['admin', 'editor', 'viewer']:
                flash('Invalid role', 'error')
                return redirect(url_for('admin_edit_user', user_id=user_id))
            
            try:
                if new_password:
                    password_hash = generate_password_hash(new_password)
                    conn.execute('''
                        UPDATE users 
                        SET role = ?, email = ?, first_name = ?, last_name = ?, team = ?, password_hash = ?
                        WHERE id = ?
                    ''', (role, email, first_name, last_name, team, password_hash, user_id))
                else:
                    conn.execute('''
                        UPDATE users 
                        SET role = ?, email = ?, first_name = ?, last_name = ?, team = ?
                        WHERE id = ?
                    ''', (role, email, first_name, last_name, team, user_id))
                
                conn.commit()
                flash(f'User "{user["username"]}" updated successfully!', 'success')
                return redirect(url_for('admin_users'))
                
            except Exception as e:
                flash(f'Error updating user: {str(e)}', 'error')
        
        return render_template('admin_edit_user.html', user=user)

@app.route('/admin/users/<int:user_id>/toggle-active', methods=['POST'])
@admin_required
def toggle_user_active(user_id):
    """Toggle user active/inactive status"""
    try:
        with get_db_connection() as conn:
            user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            
            if not user:
                return jsonify({'success': False, 'error': 'User not found'}), 404
            
            # Prevent deactivating yourself
            if user_id == session.get('user_id'):
                return jsonify({'success': False, 'error': 'You cannot deactivate your own account'}), 400
            
            new_status = 0 if user['is_active'] else 1
            conn.execute('UPDATE users SET is_active = ? WHERE id = ?', (new_status, user_id))
            conn.commit()
            
            status_text = 'activated' if new_status else 'deactivated'
            return jsonify({'success': True, 'is_active': new_status, 'message': f'User {status_text} successfully'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Delete a user (non-admin users only)"""
    try:
        with get_db_connection() as conn:
            user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            
            if not user:
                return jsonify({'success': False, 'error': 'User not found'}), 404
            
            # Prevent deleting yourself
            if user_id == session.get('user_id'):
                return jsonify({'success': False, 'error': 'You cannot delete your own account'}), 400
            
            # Prevent deleting other admins
            if user['role'] == 'admin':
                return jsonify({'success': False, 'error': 'Cannot delete admin users. Demote them first.'}), 400
            
            conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()
            
            return jsonify({'success': True, 'message': f'User "{user["username"]}" deleted successfully'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/recipes')
@login_required
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
@editor_required
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
@login_required
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
@editor_required
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
@editor_required
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
@login_required
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
@editor_required
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
            
            # Check if system already exists with this serial number + RSCM location
            with get_db_connection() as conn:
                existing = conn.execute(
                    'SELECT id FROM systems WHERE name = ? AND rscm_ip = ? AND rscm_port = ?', 
                    (serial_number, rscm_ip, system_port)
                ).fetchone()
                
                if existing:
                    flash(f'System with serial number {serial_number} at {rscm_ip}:{system_port} already exists!', 'warning')
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
@editor_required
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
@login_required
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
@editor_required
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
@editor_required
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
@login_required
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
        
        # Get firmware types available for this system's program
        if system['program_id']:
            # Filter firmware types by program association
            firmware_types = conn.execute('''
                SELECT ft.* 
                FROM firmware_types ft
                INNER JOIN program_firmware_types pft ON ft.id = pft.firmware_type_id
                WHERE pft.program_id = ?
                ORDER BY ft.category, ft.name
            ''', (system['program_id'],)).fetchall()
        else:
            # No program assigned - show all firmware types
            firmware_types = conn.execute('''
                SELECT * FROM firmware_types ORDER BY category, name
            ''').fetchall()
        
        # Group firmware types by category for display
        firmware_by_category = {}
        for ft in firmware_types:
            if ft['category'] not in firmware_by_category:
                firmware_by_category[ft['category']] = []
            firmware_by_category[ft['category']].append(ft)
        
        # Load available recipes for selection (filtered by program)
        if system['program_id']:
            recipes = conn.execute('''
                SELECT id, name FROM firmware_recipes 
                WHERE program_id = ? OR program_id IS NULL
                ORDER BY name
            ''', (system['program_id'],)).fetchall()
        else:
            recipes = conn.execute('SELECT id, name FROM firmware_recipes ORDER BY name').fetchall()
    
    # Extract hostname from description if present
    system_hostname = None
    if system['description'] and 'Host:' in system['description']:
        # Extract hostname: "Host: <hostname> | ..." -> "<hostname>"
        try:
            host_part = system['description'].split('Host:')[1].split('|')[0].strip()
            system_hostname = host_part
        except (IndexError, AttributeError):
            system_hostname = None
    
    return render_template('check_firmware.html', 
                         system=system, 
                         active_check=active_check, 
                         system_hostname=system_hostname, 
                         recipes=recipes,
                         firmware_by_category=firmware_by_category)

@app.route('/check/<int:system_id>/progress')
@login_required
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
@login_required
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
@login_required
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
@login_required
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
                ORDER BY check_date DESC 
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
@login_required
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
@login_required
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
@login_required
def test_redfish():
    """Serve the Redfish connection test page"""
    import os
    test_file_path = os.path.join(os.path.dirname(__file__), 'test_redfish.html')
    with open(test_file_path, 'r') as f:
        return f.read(), 200, {'Content-Type': 'text/html'}

@app.route('/api/test-connection', methods=['POST'])
@login_required
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
@login_required
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
@admin_required
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

@app.route('/api/restart-application', methods=['POST'])
@admin_required
def api_restart_application():
    """API endpoint to restart the Flask application"""
    try:
        # Check if any firmware checks are currently running
        with active_checks_lock:
            if len(active_checks) > 0:
                active_list = []
                for check_id, info in active_checks.items():
                    with get_db_connection() as conn:
                        check = conn.execute('''
                            SELECT fc.id, s.name as system_name, s.rscm_ip
                            FROM firmware_checks fc
                            JOIN systems s ON fc.system_id = s.id
                            WHERE fc.id = ?
                        ''', (check_id,)).fetchone()
                        
                        if check:
                            active_list.append({
                                'check_id': check_id,
                                'system_name': check['system_name'],
                                'rscm_ip': check['rscm_ip'],
                                'runtime_minutes': (time.time() - info['start_time']) / 60
                            })
                
                return jsonify({
                    'status': 'blocked',
                    'message': 'Cannot restart while firmware checks are running',
                    'active_checks': active_list,
                    'active_count': len(active_checks)
                }), 400
        
        # No active checks, safe to restart
        logger.info("Application restart requested - shutting down gracefully...")
        
        # Shutdown thread pool
        def shutdown_and_restart():
            time.sleep(1)  # Give time for response to be sent
            thread_pool.shutdown(wait=False)
            logger.info("Restarting application...")
            os.execv(sys.executable, [sys.executable] + sys.argv)
        
        # Start shutdown in background thread
        restart_thread = threading.Thread(target=shutdown_and_restart, daemon=True)
        restart_thread.start()
        
        return jsonify({
            'status': 'success',
            'message': 'Application is restarting...'
        })
        
    except Exception as e:
        logger.error(f"Error restarting application: {str(e)}")
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
    
    # Create default admin user if needed
    create_default_admin()
    
    # Cleanup orphaned running checks on startup
    cleanup_orphaned_checks()
    
    print("Starting web server on http://0.0.0.0:5000")
    print("Access the application at: http://localhost:5000")
    print("=" * 80)
    print("Console output will show firmware check progress...")
    print("=" * 80)
    
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)