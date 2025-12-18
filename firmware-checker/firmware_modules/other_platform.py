"""
Other Platform Firmware Checker Module
Handles checking firmware versions for other platform components
"""

import logging
import requests
import json
from datetime import datetime
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning
import urllib3
from .storage_firmware import StorageFirmwareChecker
from .os_version import OSVersionChecker
from .dimm_info import DIMMInfoChecker

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)

class OtherPlatformChecker:
    """Checker for other platform firmware components"""
    
    def __init__(self, username='admin', password='admin', timeout=30, os_username=None, os_password=None):
        self.firmware_types = [
            'HPMCpld',
            'SOC VR Configs',
            'E.1s',
            'M.2',
            'Windows OS Version',
            'DIMM Information'
        ]
        
        # Credentials for Redfish API access
        self.username = username
        self.password = password
        self.timeout = timeout
        
        # OS credentials for storage firmware checks
        self.os_username = os_username
        self.os_password = os_password
        
        # Initialize storage firmware checker
        self.storage_checker = StorageFirmwareChecker(
            os_username=os_username, 
            os_password=os_password,
            timeout=timeout
        )
        
        # Initialize OS version checker
        self.os_version_checker = OSVersionChecker(
            os_username=os_username,
            os_password=os_password,
            timeout=timeout
        )
        
        # Initialize DIMM info checker
        self.dimm_checker = DIMMInfoChecker(
            os_username=os_username,
            os_password=os_password,
            timeout=timeout
        )
    
    def check_all(self, rscm_ip, system_port=5, computer_name=None):
        """Check all other platform firmware versions using Redfish API and storage tools
        
        Args:
            rscm_ip: RSCM IP address (e.g., 172.29.89.27)
            system_port: System port/slot number (e.g., 5) - this was rscm_port in the old system
            computer_name: Computer name for storage firmware checks (optional, defaults to rscm_ip)
        """
        logger.info(f"Checking Other Platform firmware for {rscm_ip}:{system_port}")
        print(f"[OTHER] Starting Other Platform firmware check for {rscm_ip}:{system_port}")
        
        results = {
            'category': 'Other Platform',
            'timestamp': datetime.now().isoformat(),
            'rscm_ip': rscm_ip,
            'system_port': system_port,
            'status': 'completed',
            'firmware_versions': {},
            'errors': []
        }
        
        try:
            # Get system information from Redfish API to extract HPMCpld
            print(f"[OTHER] Fetching system data from Redfish API...")
            system_data = self._get_redfish_data(rscm_ip, system_port, '/redfish/v1/System')
            
            if system_data:
                print(f"[OTHER] System data retrieved, extracting HPMCpld version...")
                # Extract HPMCpld version from the same system data used by DC-SCM
                results['firmware_versions']['HPMCpld'] = self._extract_hpm_cpld_version(system_data)
                print(f"[OTHER] HPMCpld extraction completed")
            else:
                print(f"[OTHER] Failed to get system data from Redfish API")
                results['firmware_versions']['HPMCpld'] = {
                    'version': 'CONNECTION_FAILED',
                    'status': 'error',
                    'error': 'Failed to connect to Redfish API',
                    'checked_at': datetime.now().isoformat()
                }
            
            # Check if we have OS credentials for in-band storage checks
            if self.os_username and self.os_password and computer_name:
                # We have credentials and a target computer - perform storage checks
                print(f"[OTHER] Checking storage firmware on {computer_name} with OS credentials...")
                
                # Check M.2 devices - now returns combined format
                m2_results = self.storage_checker.get_m2_devices(computer_name)
                results['firmware_versions']['M.2'] = m2_results
                
                # Check E.1s devices - now returns combined format
                e1s_results = self.storage_checker.get_e1s_devices(computer_name)
                results['firmware_versions']['E.1s'] = e1s_results
                
                print(f"[OTHER] Storage firmware checks completed")
            else:
                # No OS credentials or target computer - skip in-band storage checks
                if not self.os_username or not self.os_password:
                    skip_reason = "No OS credentials provided"
                    print(f"[OTHER] Skipping storage firmware checks: {skip_reason}")
                elif not computer_name:
                    skip_reason = "No target computer specified"
                    print(f"[OTHER] Skipping storage firmware checks: {skip_reason}")
                else:
                    skip_reason = "Missing requirements"
                
                # Return error status for storage devices when credentials not provided
                storage_result = {
                    'version': 'NOT CONFIGURED - OS Credentials Required',
                    'status': 'error',
                    'error': skip_reason,
                    'checked_at': datetime.now().isoformat(),
                    'method': 'storage_firmware_tool'
                }
                
                results['firmware_versions']['M.2'] = storage_result.copy()
                results['firmware_versions']['E.1s'] = storage_result.copy()
            
            # Check Windows OS Version if we have OS credentials and computer name
            if self.os_username and self.os_password and computer_name:
                # We have credentials and a target computer - check OS version
                print(f"[OTHER] Checking Windows OS version on {computer_name}...")
                os_version_result = self.os_version_checker.get_os_version(computer_name)
                results['firmware_versions']['Windows OS Version'] = os_version_result
                print(f"[OTHER] Windows OS version check completed")
            else:
                # No OS credentials or target computer - skip OS version check
                if not self.os_username or not self.os_password:
                    skip_reason = "No OS credentials provided"
                    print(f"[OTHER] Skipping OS version check: {skip_reason}")
                elif not computer_name:
                    skip_reason = "No target computer specified"
                    print(f"[OTHER] Skipping OS version check: {skip_reason}")
                else:
                    skip_reason = "Missing requirements"
                
                results['firmware_versions']['Windows OS Version'] = {
                    'version': 'NOT CONFIGURED - OS Credentials Required',
                    'status': 'error',
                    'error': skip_reason,
                    'checked_at': datetime.now().isoformat(),
                    'method': 'os_version_check'
                }
            
            # Check DIMM Information if we have OS credentials and computer name
            if self.os_username and self.os_password and computer_name:
                # We have credentials and a target computer - check DIMM info
                print(f"[OTHER] Checking DIMM information on {computer_name}...")
                dimm_info_result = self.dimm_checker.get_dimm_info(computer_name)
                results['firmware_versions']['DIMM Information'] = dimm_info_result
                print(f"[OTHER] DIMM information check completed")
            else:
                # No OS credentials or target computer - skip DIMM check
                if not self.os_username or not self.os_password:
                    skip_reason = "No OS credentials provided"
                    print(f"[OTHER] Skipping DIMM information check: {skip_reason}")
                elif not computer_name:
                    skip_reason = "No target computer specified"
                    print(f"[OTHER] Skipping DIMM information check: {skip_reason}")
                else:
                    skip_reason = "Missing requirements"
                
                results['firmware_versions']['DIMM Information'] = {
                    'version': 'NOT CONFIGURED - OS Credentials Required',
                    'status': 'error',
                    'error': skip_reason,
                    'checked_at': datetime.now().isoformat(),
                    'method': 'dimm_info_check'
                }
            
            # SOC VR Configs - still placeholder
            results['firmware_versions']['SOC VR Configs'] = self._check_firmware_placeholder('SOC VR Configs', rscm_ip, system_port)
            
            print(f"[OTHER] Other Platform firmware check section completed")
        
        except Exception as e:
            logger.error(f"Error checking Other Platform firmware: {str(e)}")
            results['status'] = 'error'
            results['errors'].append(str(e))
            
            # Fall back to error values for failed connections
            for fw_type in self.firmware_types:
                if fw_type not in results['firmware_versions']:
                    results['firmware_versions'][fw_type] = {
                        'version': 'CONNECTION_FAILED',
                        'status': 'error',
                        'error': str(e),
                        'checked_at': datetime.now().isoformat(),
                        'method': 'redfish_api' if fw_type in ['HPMCpld', 'SOC VR Configs'] else 'storage_firmware_tool'
                    }
        
        return results
    
    def _get_redfish_data(self, rscm_ip, system_port, endpoint, https_port=8080):
        """Get data from Redfish API endpoint
        
        Args:
            rscm_ip: RSCM IP address (e.g., 172.29.89.27)
            system_port: System port number (e.g., 5) - this is the "slot" in the URL
            endpoint: Redfish endpoint path (e.g., /redfish/v1/System)
            https_port: HTTPS port for RSCM (default 8080)
        """
        try:
            # Construct URL: https://{rscm_ip}:8080/{system_port}/redfish/v1/System
            url = f"https://{rscm_ip}:{https_port}/{system_port}{endpoint}"
            
            logger.debug(f"Making Redfish API call to: {url}")
            
            response = requests.get(
                url,
                auth=HTTPBasicAuth(self.username, self.password),
                verify=False,  # Disable SSL verification for self-signed certs
                timeout=self.timeout,
                headers={'Accept': 'application/json'}
            )
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Redfish API request failed for {url}: {str(e)}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response from {url}: {str(e)}")
            return None
    
    def _extract_hpm_cpld_version(self, system_data):
        """Extract HPMCpld version from system data (the generic CPLD version)"""
        try:
            # The CPLDVersion field corresponds to HPMCpld firmware
            hpm_cpld_version = system_data.get('Oem', {}).get('Microsoft', {}).get('CPLDVersion', 'Not Available')
            
            return {
                'version': hpm_cpld_version,
                'status': 'success' if hpm_cpld_version != 'Not Available' else 'not_found',
                'error': None,
                'checked_at': datetime.now().isoformat(),
                'raw_data': {
                    'CPLDVersion': hpm_cpld_version
                }
            }
        except Exception as e:
            return {
                'version': 'PARSE_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat()
            }
    
    def _check_firmware_placeholder(self, firmware_type, rscm_ip, system_port):
        """Placeholder function for individual firmware checks"""
        
        # SOC VR Configs is not yet implemented by systems development teams
        if firmware_type == 'SOC VR Configs':
            return {
                'version': 'NOT_IMPLEMENTED_BY_SYSTEMS_DEV',
                'status': 'not_implemented',
                'error': 'Not yet implemented by systems development teams',
                'checked_at': datetime.now().isoformat(),
                'note': 'Awaiting implementation by systems dev teams'
            }
        
        # Generic placeholder for other firmware types
        return {
            'version': 'PLACEHOLDER_VERSION',
            'status': 'not_implemented',
            'error': 'Implementation method not yet determined',
            'checked_at': datetime.now().isoformat()
        }
    
    def check_hpm_cpld(self, rscm_ip, rscm_port=22):
        """Check HPM CPLD version"""
        # TODO: Implement actual HPM CPLD checking logic
        pass
    
    def check_soc_vr_configs(self, rscm_ip, rscm_port=22):
        """Check SOC VR Configurations version"""
        # TODO: Implement actual SOC VR Configs checking logic
        pass
    
    def check_e1s_primary(self, rscm_ip, rscm_port=22):
        """Check E.1s Primary storage version"""
        # TODO: Implement actual E.1s Primary checking logic
        pass
    
    def check_e1s_secondary(self, rscm_ip, rscm_port=22):
        """Check E.1s Secondary storage version"""
        # TODO: Implement actual E.1s Secondary checking logic
        pass
    
    def check_m2_primary(self, rscm_ip, rscm_port=22):
        """Check M.2 Primary storage version"""
        # TODO: Implement actual M.2 Primary checking logic
        pass
    
    def check_m2_secondary(self, rscm_ip, rscm_port=22):
        """Check M.2 Secondary storage version"""
        # TODO: Implement actual M.2 Secondary checking logic
        pass
    
    def check_individual_firmware(self, firmware_type, rscm_ip, system_port=5, computer_name=None):
        """Check individual firmware type with detailed progress
        
        Args:
            firmware_type: Name of the firmware type to check
            rscm_ip: RSCM IP address
            system_port: System port/slot number
            computer_name: Windows computer name for storage firmware checks (optional)
            
        Returns:
            Dictionary with firmware version information
        """
        print(f"[OTHER] Checking individual firmware: {firmware_type}")
        
        try:
            # Map firmware types to their checking methods
            if firmware_type == 'HPMCpld':
                return self._check_hpm_cpld_individual(rscm_ip, system_port)
            elif firmware_type in ['M.2', 'M.2(Primary)', 'M.2(Secondary)']:
                # Use provided computer_name for storage checks, fallback to rscm_ip if not provided
                target_computer = computer_name if computer_name else rscm_ip
                if self.os_username and self.os_password:
                    return self.storage_checker.get_m2_devices(target_computer)
                else:
                    return {
                        'version': 'NOT CONFIGURED - OS Credentials Required',
                        'status': 'error',
                        'error': 'No OS credentials provided for Windows storage firmware check',
                        'checked_at': datetime.now().isoformat(),
                        'method': 'storage_firmware_tool'
                    }
            elif firmware_type in ['E.1s', 'E.1s(primary)', 'E.1s (Secondary)']:
                # Use provided computer_name for storage checks, fallback to rscm_ip if not provided
                target_computer = computer_name if computer_name else rscm_ip
                if self.os_username and self.os_password:
                    return self.storage_checker.get_e1s_devices(target_computer)
                else:
                    return {
                        'version': 'NOT CONFIGURED - OS Credentials Required',
                        'status': 'error',
                        'error': 'No OS credentials provided for Windows storage firmware check',
                        'checked_at': datetime.now().isoformat(),
                        'method': 'storage_firmware_tool'
                    }
            elif firmware_type == 'Windows OS Version':
                # Use provided computer_name for OS version check, fallback to rscm_ip if not provided
                target_computer = computer_name if computer_name else rscm_ip
                if self.os_username and self.os_password:
                    return self.os_version_checker.get_os_version(target_computer)
                else:
                    return {
                        'version': 'NOT CONFIGURED - OS Credentials Required',
                        'status': 'error',
                        'error': 'No OS credentials provided for Windows OS version check',
                        'checked_at': datetime.now().isoformat(),
                        'method': 'os_version_check'
                    }
            elif firmware_type == 'DIMM Information':
                # Use provided computer_name for DIMM info check, fallback to rscm_ip if not provided
                target_computer = computer_name if computer_name else rscm_ip
                if self.os_username and self.os_password:
                    return self.dimm_checker.get_dimm_info(target_computer)
                else:
                    return {
                        'version': 'NOT CONFIGURED - OS Credentials Required',
                        'status': 'error',
                        'error': 'No OS credentials provided for DIMM information check',
                        'checked_at': datetime.now().isoformat(),
                        'method': 'dimm_info_check'
                    }
            else:
                return self._check_firmware_placeholder(firmware_type, rscm_ip, system_port)
        
        except Exception as e:
            logger.error(f"Error checking individual Other Platform firmware {firmware_type}: {str(e)}")
            return {
                'version': 'EXCEPTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'individual_check'
            }
    
    def _check_hpm_cpld_individual(self, rscm_ip, system_port):
        """Check HPMCpld using Redfish API"""
        try:
            system_data = self._get_redfish_data(rscm_ip, system_port, '/redfish/v1/System')
            if system_data:
                return self._extract_hpm_cpld_version(system_data)
            else:
                return {
                    'version': 'CONNECTION_FAILED',
                    'status': 'error',
                    'error': 'Failed to connect to Redfish API',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'redfish_api'
                }
        except Exception as e:
            return {
                'version': 'EXCEPTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'redfish_api'
            }