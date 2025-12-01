#!/usr/bin/env python3
"""
Script to sanitize existing hostnames in the database:
1. Remove domain suffixes (.redmond.corp.microsoft.com, etc.)
2. Extract and populate U-height from hostname pattern if missing
"""

import sqlite3
import re
from contextlib import contextmanager

DB_PATH = 'firmware_checker.db'

@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def sanitize_hostname(hostname):
    """Remove domain suffixes from hostnames"""
    if not hostname:
        return hostname
    
    domains_to_remove = [
        '.redmond.corp.microsoft.com',
        '.corp.microsoft.com',
        '.microsoft.com'
    ]
    
    hostname_cleaned = hostname.strip()
    for domain in domains_to_remove:
        if hostname_cleaned.lower().endswith(domain.lower()):
            hostname_cleaned = hostname_cleaned[:-len(domain)]
            break
    
    return hostname_cleaned

def extract_u_height_from_hostname(hostname):
    """
    Extract U-height from hostname pattern
    Examples: 
        "C41431157B0603A" -> rack "B06", u_height "3"
        "C41431065C0435A" -> rack "C04", u_height "35"
    """
    if not hostname:
        return None, None
    
    # Pattern: ends with letter + 2 digits + 2 digits + letter
    match = re.search(r'([A-Z])(\d{2})(\d{2})([A-Z])$', hostname)
    
    if match:
        rack_letter = match.group(1)
        rack_number = match.group(2)
        u_height_raw = match.group(3)
        
        try:
            u_height = str(int(u_height_raw))
            rack_name = f"{rack_letter}{rack_number}-Rack"
            return rack_name, u_height
        except ValueError:
            pass
    
    return None, None

def sanitize_all_hostnames():
    """Sanitize all hostnames and extract U-heights"""
    with get_db_connection() as conn:
        systems = conn.execute('''
            SELECT id, description, u_height
            FROM systems
            WHERE description IS NOT NULL AND description != ''
        ''').fetchall()
        
        print(f"\nProcessing {len(systems)} systems...\n")
        
        hostnames_cleaned = 0
        u_heights_extracted = 0
        no_change = 0
        
        for system in systems:
            description = system['description']
            current_u_height = system['u_height']
            
            # Extract hostname from description
            hostname = None
            if description and 'Host:' in description:
                parts = description.split('|')
                for part in parts:
                    part = part.strip()
                    if part.startswith('Host:'):
                        hostname = part.replace('Host:', '').strip()
                        break
            
            if not hostname:
                no_change += 1
                continue
            
            # Sanitize hostname
            original_hostname = hostname
            cleaned_hostname = sanitize_hostname(hostname)
            
            # Extract U-height if missing
            new_u_height = current_u_height
            if not current_u_height:
                detected_rack, detected_u = extract_u_height_from_hostname(cleaned_hostname)
                if detected_u:
                    new_u_height = detected_u
            
            # Check if anything changed
            hostname_changed = cleaned_hostname != original_hostname
            u_height_changed = new_u_height and new_u_height != current_u_height
            
            if hostname_changed or u_height_changed:
                # Rebuild description with cleaned hostname
                new_description = description.replace(f"Host: {original_hostname}", f"Host: {cleaned_hostname}")
                
                # Update database
                conn.execute('''
                    UPDATE systems 
                    SET description = ?, u_height = ?
                    WHERE id = ?
                ''', (new_description, new_u_height, system['id']))
                
                print(f"System {system['id']}:")
                if hostname_changed:
                    print(f"  Hostname: '{original_hostname}' -> '{cleaned_hostname}'")
                    hostnames_cleaned += 1
                if u_height_changed:
                    print(f"  U-height: {current_u_height or 'NULL'} -> {new_u_height}")
                    u_heights_extracted += 1
                print()
            else:
                no_change += 1
        
        print(f"\n{'='*70}")
        print(f"SUMMARY")
        print(f"{'='*70}")
        print(f"✓ Hostnames cleaned: {hostnames_cleaned}")
        print(f"✓ U-heights extracted: {u_heights_extracted}")
        print(f"✓ No change needed: {no_change}")
        print(f"{'='*70}\n")

if __name__ == '__main__':
    print("="*70)
    print("HOSTNAME SANITIZATION & U-HEIGHT EXTRACTION")
    print("="*70)
    sanitize_all_hostnames()
