"""
DC-SCM Firmware Checker Module
Handles checking firmware versions for DC-SCM components using Redfish API
"""

import logging
import requests
import json
import re
import time
from datetime import datetime
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning
import urllib3
import paramiko

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)

class DCScmChecker:
    """Checker for DC-SCM firmware components using Redfish API"""
    
    def __init__(self, username='admin', password='admin', timeout=30):
        self.firmware_types = [
            'IFWI',
            'UEFI Profile/Other',
            'BMC FW', 
            'Inventory',
            'PowerCapping',
            'FanTable',
            'SDRGenerator',
            'IPMIAllowList',
            'BMC Tip',
            'BMC TIP PCD Platform ID',
            'BMC TIP PCD Version ID (hex)/(dec)',
            'Manticore (HSM)',
            'CFM Platform ID',
            'CFM Version ID (hex)/(dec)',
            'TPM Module',
            'SCM-CPLD'
        ]
        
        # Default credentials - should be configurable
        self.username = username
        self.password = password
        self.timeout = timeout
        
        # Common Redfish endpoints
        self.base_endpoints = {
            'system': '/redfish/v1/System',
            'managers': '/redfish/v1/Managers/System',
            'chassis': '/redfish/v1/Chassis/System',
            'biosconfig': '/redfish/v1/System/BiosConfig',
            'frudata': '/redfish/v1/System/FRUData'
        }
    
    def check_all(self, rscm_ip, system_port=5):
        """Check all DC-SCM firmware versions using Redfish API
        
        Args:
            rscm_ip: RSCM IP address (e.g., 172.29.89.27)
            system_port: System port/slot number (e.g., 5) - this was rscm_port in the old system
        """
        logger.info(f"Checking DC-SCM firmware for RSCM {rscm_ip}, system port {system_port}")
        print(f"[DC-SCM] Starting DC-SCM firmware check for {rscm_ip}:{system_port}")
        
        results = {
            'category': 'DC-SCM',
            'timestamp': datetime.now().isoformat(),
            'rscm_ip': rscm_ip,
            'system_port': system_port,
            'status': 'success',
            'firmware_versions': {},
            'connection_info': None,
            'errors': []
        }
        
        try:
            # First test if Redfish is available
            print(f"[DC-SCM] Testing Redfish connection...")
            connection_test = self.test_redfish_connection(rscm_ip, system_port)
            if connection_test['status'] != 'success':
                print(f"[DC-SCM] Redfish connection failed: {connection_test['message']}")
                results['status'] = 'error'
                results['errors'].append(connection_test['message'])
                return results
            
            print(f"[DC-SCM] Redfish connection successful")
            
            # Get system information from Redfish API
            print(f"[DC-SCM] Fetching system information from Redfish API...")
            system_data = self._get_redfish_data(rscm_ip, system_port, self.base_endpoints['system'])
            
            if system_data:
                print(f"[DC-SCM] System information retrieved successfully")
                results['connection_info'] = {
                    'system_id': system_data.get('Id', 'Unknown'),
                    'system_name': system_data.get('Name', 'Unknown'),
                    'manufacturer': system_data.get('Manufacturer', 'Unknown'),
                    'model': system_data.get('Model', 'Unknown'),
                    'serial_number': system_data.get('SerialNumber', 'Unknown')
                }
                
                # Extract firmware versions from system data
                print(f"[DC-SCM] Extracting BIOS/IFWI version...")
                results['firmware_versions']['IFWI'] = self._extract_bios_version(system_data)
                print(f"[DC-SCM] Extracting BMC version...")
                results['firmware_versions']['BMC FW'] = self._extract_bmc_version(system_data)
                print(f"[DC-SCM] Extracting SCM-CPLD version...")
                results['firmware_versions']['SCM-CPLD'] = self._extract_scm_cpld_version(system_data)
                
                # Get additional firmware information from other endpoints
                print(f"[DC-SCM] Fetching additional firmware information...")
                self._get_additional_firmware_info(rscm_ip, system_port, results)
                print(f"[DC-SCM] Additional firmware information completed")
            else:
                print(f"[DC-SCM] Failed to get system data from Redfish API")
                results['status'] = 'error'
                results['errors'].append('Failed to connect to Redfish API')
                
        except Exception as e:
            logger.error(f"Error checking DC-SCM firmware: {str(e)}")
            results['status'] = 'error'
            results['errors'].append(str(e))
            
            # Fall back to placeholder values for failed connections
            for fw_type in self.firmware_types:
                if fw_type not in results['firmware_versions']:
                    results['firmware_versions'][fw_type] = {
                        'version': 'CONNECTION_FAILED',
                        'status': 'error',
                        'error': str(e),
                        'checked_at': datetime.now().isoformat()
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
    
    def test_redfish_connection(self, rscm_ip, system_port=5, https_port=8080):
        """Test if Redfish is enabled on the RSCM by testing the System endpoint"""
        try:
            # Test the System endpoint since we know this works
            url = f"https://{rscm_ip}:{https_port}/{system_port}/redfish/v1/System"
            
            logger.debug(f"Testing Redfish connection to: {url}")
            
            response = requests.get(
                url,
                auth=HTTPBasicAuth(self.username, self.password),
                verify=False,
                timeout=self.timeout,
                headers={'Accept': 'application/json'}
            )
            
            response.raise_for_status()
            data = response.json()
            
            return {
                'status': 'success',
                'message': 'Redfish API is available',
                'rack_manager_info': {
                    'id': data.get('Id', 'Unknown'),
                    'name': data.get('Name', 'Unknown'),
                    'manager_type': data.get('SystemType', 'Unknown'),
                    'firmware_version': data.get('BiosVersion', 'Unknown')
                }
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Redfish connection test failed: {str(e)}")
            return {
                'status': 'error',
                'message': f'Failed to connect to Redfish API: {str(e)}',
                'rack_manager_info': None
            }
    
    def _extract_bios_version(self, system_data):
        """Extract BIOS/IFWI version from system data"""
        try:
            bios_version = system_data.get('BiosVersion', 'Not Available')
            return {
                'version': bios_version,
                'status': 'success' if bios_version != 'Not Available' else 'not_found',
                'error': None,
                'checked_at': datetime.now().isoformat(),
                'raw_data': bios_version
            }
        except Exception as e:
            return {
                'version': 'PARSE_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat()
            }
    
    def _extract_bmc_version(self, system_data):
        """Extract BMC version from system data"""
        try:
            bmc_version = system_data.get('Oem', {}).get('Microsoft', {}).get('BMCVersion', 'Not Available')
            return {
                'version': bmc_version,
                'status': 'success' if bmc_version != 'Not Available' else 'not_found',
                'error': None,
                'checked_at': datetime.now().isoformat(),
                'raw_data': bmc_version
            }
        except Exception as e:
            return {
                'version': 'PARSE_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat()
            }
    
    def _extract_scm_cpld_version(self, system_data):
        """Extract SCM-CPLD version from system data (DCSCM CPLD only)"""
        try:
            # Only get the DCSCM CPLD version for SCM-CPLD firmware type
            scm_cpld_version = system_data.get('Oem', {}).get('Microsoft', {}).get('DCSCMCPLDVersion', 'Not Available')
            
            return {
                'version': scm_cpld_version,
                'status': 'success' if scm_cpld_version != 'Not Available' else 'not_found',
                'error': None,
                'checked_at': datetime.now().isoformat(),
                'raw_data': {
                    'DCSCMCPLDVersion': scm_cpld_version
                }
            }
        except Exception as e:
            return {
                'version': 'PARSE_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat()
            }
    

    def _get_additional_firmware_info(self, rscm_ip, system_port, results):
        """Get additional firmware information using SSH IPMI commands and Redfish endpoints"""
        try:
            logger.info(f"Getting additional firmware info using SSH IPMI commands")
            
            # Get BMC configuration versions using SSH IPMI commands
            # These correspond to the PowerShell Invoke-GetConfigVersion function
            ssh_ipmi_components = {
                'PowerCapping': 'PowerCapping',    # Maps to PowerCapping in firmware_types
                'SDRGen': 'SDRGenerator',          # Maps to SDRGenerator in firmware_types  
                'FanTable': 'FanTable',           # Maps to FanTable in firmware_types
                'Inventory': 'Inventory'          # Maps to Inventory in firmware_types
            }
            
            for ssh_component, fw_type in ssh_ipmi_components.items():
                logger.debug(f"Getting {fw_type} version via SSH IPMI command '{ssh_component}'")
                
                if fw_type in self.firmware_types:
                    results['firmware_versions'][fw_type] = self._get_bmc_config_version(
                        rscm_ip, system_port, ssh_component
                    )
            
            # Get Manticore (HSM) firmware version using Redfish Cerberus endpoint
            try:
                logger.debug(f"Getting Manticore (HSM) version via Redfish Cerberus endpoint")
                if 'Manticore (HSM)' in self.firmware_types:
                    cerberus_data = self._get_redfish_data(rscm_ip, system_port, '/redfish/v1/System/Cerberus/1')
                    if cerberus_data:
                        results['firmware_versions']['Manticore (HSM)'] = self._extract_cerberus_version(cerberus_data)
                    else:
                        results['firmware_versions']['Manticore (HSM)'] = {
                            'version': 'CONNECTION_FAILED',
                            'status': 'error',
                            'error': 'Failed to connect to Cerberus Redfish endpoint',
                            'checked_at': datetime.now().isoformat()
                        }
            except Exception as manticore_error:
                logger.warning(f"Failed to get Manticore (HSM) firmware info: {str(manticore_error)}")
            
            # Get BMC Tip firmware version using SSH Cerberus command
            try:
                logger.debug(f"Getting BMC Tip version via SSH Cerberus command")
                if 'BMC Tip' in self.firmware_types:
                    results['firmware_versions']['BMC Tip'] = self._get_cerberus_ssh_version(rscm_ip, system_port, 'BMC Tip', component_code='2')
            except Exception as bmctip_error:
                logger.warning(f"Failed to get BMC Tip firmware info: {str(bmctip_error)}")
            
            # Get BMC TIP PCD firmware versions (not yet implemented by systems dev teams)
            try:
                logger.debug(f"Getting BMC TIP PCD firmware versions (placeholder - not implemented by systems dev teams)")
                
                # BMC TIP PCD Platform ID - not yet implemented by systems dev teams
                if 'BMC TIP PCD Platform ID' in self.firmware_types:
                    results['firmware_versions']['BMC TIP PCD Platform ID'] = {
                        'version': 'NOT_IMPLEMENTED_BY_SYSTEMS_DEV',
                        'status': 'not_implemented',
                        'error': 'Not yet implemented by systems development teams',
                        'checked_at': datetime.now().isoformat(),
                        'note': 'Awaiting implementation by systems dev teams'
                    }
                
                # BMC TIP PCD Version ID (hex)/(dec) - not yet implemented by systems dev teams  
                if 'BMC TIP PCD Version ID (hex)/(dec)' in self.firmware_types:
                    results['firmware_versions']['BMC TIP PCD Version ID (hex)/(dec)'] = {
                        'version': 'NOT_IMPLEMENTED_BY_SYSTEMS_DEV',
                        'status': 'not_implemented', 
                        'error': 'Not yet implemented by systems development teams',
                        'checked_at': datetime.now().isoformat(),
                        'note': 'Awaiting implementation by systems dev teams - should return hex and decimal format'
                    }
                
                # Add placeholder implementations for other firmware types not yet implemented
                placeholder_firmware_types = [
                    'IPMIAllowList', 
                    'CFM Platform ID',
                    'CFM Version ID (hex)/(dec)',
                    'TPM Module'
                ]
                
                for fw_type in placeholder_firmware_types:
                    if fw_type in self.firmware_types:
                        results['firmware_versions'][fw_type] = {
                            'version': 'NOT_IMPLEMENTED',
                            'status': 'not_implemented',
                            'error': 'Implementation method not yet determined',
                            'checked_at': datetime.now().isoformat(),
                            'note': 'Requires endpoint discovery or additional command methods'
                        }
                    
            except Exception as pcd_error:
                logger.warning(f"Failed to process BMC TIP PCD firmware types: {str(pcd_error)}")
            
            # Try to get additional Redfish data for other firmware types
            try:
                # Try to get BIOS config for additional firmware info  
                bios_config = self._get_redfish_data(rscm_ip, system_port, self.base_endpoints['biosconfig'])
                if bios_config:
                    # Parse BIOS config for additional firmware versions
                    self._parse_bios_config_data(bios_config, results)
            except Exception as redfish_error:
                logger.warning(f"Failed to get Redfish BIOS config: {str(redfish_error)}")
                
        except Exception as e:
            logger.warning(f"Failed to get additional firmware info: {str(e)}")
            
        # Add placeholder entries for firmware types we couldn't retrieve
        for fw_type in self.firmware_types:
            if fw_type not in results['firmware_versions']:
                results['firmware_versions'][fw_type] = {
                    'version': 'NOT_IMPLEMENTED',
                    'status': 'not_implemented',
                    'error': 'Endpoint not implemented yet',
                    'checked_at': datetime.now().isoformat()
                }
    
    def _parse_inventory_data(self, fru_data):
        """Parse FRU data for inventory information"""
        try:
            # This would need to be implemented based on the actual FRU data structure
            return {
                'version': 'FRU_DATA_AVAILABLE',
                'status': 'success',
                'error': None,
                'checked_at': datetime.now().isoformat(),
                'raw_data': fru_data
            }
        except Exception as e:
            return {
                'version': 'PARSE_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat()
            }
    
    def _parse_bios_config_data(self, bios_config, results):
        """Parse BIOS config data for additional firmware versions"""
        try:
            if not bios_config:
                logger.warning("No BIOS config data provided")
                return
                
            # Extract BIOS configuration information
            current_config = bios_config.get('CurrentConfiguration', '').strip()
            available_configs = bios_config.get('AvailableConfigurations', [])
            
            logger.debug(f"BIOS Current Configuration: {current_config}")
            logger.debug(f"BIOS Available Configurations: {available_configs}")
            
            # Map current configuration value to configuration name
            config_name = self._map_bios_config_value(current_config, available_configs)
            
            # Add UEFI Profile/Other firmware type based on BIOS config
            if 'UEFI Profile/Other' in self.firmware_types:
                results['firmware_versions']['UEFI Profile/Other'] = {
                    'version': f"{config_name} ({current_config})" if config_name else current_config,
                    'status': 'success',
                    'error': None,
                    'checked_at': datetime.now().isoformat(),
                    'method': 'redfish_bios_config',
                    'raw_config': current_config,
                    'config_name': config_name
                }
                
        except Exception as e:
            logger.warning(f"Failed to parse BIOS config data: {str(e)}")
            # Add error entry for UEFI Profile/Other
            if 'UEFI Profile/Other' in self.firmware_types:
                results['firmware_versions']['UEFI Profile/Other'] = {
                    'version': 'BIOS_CONFIG_ERROR',
                    'status': 'error',
                    'error': str(e),
                    'checked_at': datetime.now().isoformat(),
                    'method': 'redfish_bios_config'
                }
    
    def _map_bios_config_value(self, current_value, available_configs):
        """Map BIOS configuration current value to configuration name
        
        Args:
            current_value: Current configuration value (e.g., "0.0")
            available_configs: List of available configurations with Name and Value
            
        Returns:
            Configuration name (e.g., "GN") or None if not found
        """
        try:
            # Remove whitespace from current value for comparison
            current_value_clean = current_value.strip()
            
            # Search through available configurations to find matching value
            for config in available_configs:
                config_value = str(config.get('Value', '')).strip()
                config_name = config.get('Name', '')
                
                if config_value == current_value_clean:
                    logger.debug(f"Mapped BIOS config value '{current_value_clean}' to name '{config_name}'")
                    return config_name
            
            logger.warning(f"No matching configuration found for value '{current_value_clean}'")
            return None
            
        except Exception as e:
            logger.error(f"Error mapping BIOS config value: {str(e)}")
            return None
    
    def set_credentials(self, username, password):
        """Set authentication credentials for Redfish API"""
        self.username = username
        self.password = password
    
    def _extract_cerberus_version(self, cerberus_data):
        """Extract Manticore firmware version from Cerberus endpoint data
        
        If FirmwareVersion is not available, checks @Message.ExtendedInfo for error details
        from Microsoft.Description field.
        """
        try:
            # Extract firmware version from Cerberus endpoint response
            firmware_version = cerberus_data.get('FirmwareVersion', 'Not Available')
            
            # If firmware version not found, check for error description in ExtendedInfo
            if firmware_version == 'Not Available':
                extended_info = cerberus_data.get('@Message.ExtendedInfo', [])
                if extended_info and len(extended_info) > 0:
                    # Look for Microsoft.Description in the first ExtendedInfo message
                    oem = extended_info[0].get('Oem', {})
                    microsoft = oem.get('Microsoft', {})
                    description = microsoft.get('Description', '')
                    
                    if description:
                        logger.info(f"Manticore firmware version not available, found description: {description}")
                        return {
                            'version': description,
                            'status': 'success',
                            'error': None,
                            'checked_at': datetime.now().isoformat(),
                            'raw_data': {
                                'FirmwareVersion': 'Not Available',
                                'Name': cerberus_data.get('Name', 'Unknown'),
                                'Id': cerberus_data.get('Id', 'Unknown'),
                                'Description': description,
                                'CompletionCode': microsoft.get('CompletionCode', 'Unknown')
                            },
                            'note': 'Firmware version not available, returning error description from RSCM'
                        }
            
            return {
                'version': firmware_version,
                'status': 'success' if firmware_version != 'Not Available' else 'not_found',
                'error': None,
                'checked_at': datetime.now().isoformat(),
                'raw_data': {
                    'FirmwareVersion': firmware_version,
                    'Name': cerberus_data.get('Name', 'Unknown'),
                    'Id': cerberus_data.get('Id', 'Unknown')
                }
            }
        except Exception as e:
            return {
                'version': 'PARSE_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat()
            }
    
    def _get_cerberus_ssh_version(self, rscm_ip, system_port, firmware_name, component_code):
        """Get Cerberus-based firmware version using SSH command
        
        Args:
            rscm_ip: RSCM IP address
            system_port: System port/slot number (used as -i parameter)
            firmware_name: Name of firmware for logging (e.g., 'BMCTip')
            component_code: Component code for Cerberus command (1=Manticore, 2=BMCTip)
            
        Returns:
            Dictionary with firmware version information
        """
        try:
            # Command: show system cerberus version -i {port} -t 0 -b 0 -c {component_code}
            command = f"show system cerberus version -i {system_port} -t 0 -b 0 -c {component_code}"
            
            logger.debug(f"Executing SSH Cerberus command for {firmware_name}: {command}")
            
            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect using SSH (typically port 22)
            ssh.connect(
                hostname=rscm_ip,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                port=22
            )
            
            # Execute the command
            stdin, stdout, stderr = ssh.exec_command(command, timeout=30)
            
            # Get the output
            output = stdout.read().decode('utf-8')
            error_output = stderr.read().decode('utf-8')
            exit_status = stdout.channel.recv_exit_status()
            
            # Close SSH connection
            ssh.close()
            
            logger.debug(f"SSH Cerberus command output for {firmware_name}: {output}")
            
            # Parse the output to extract firmware version
            version = self._parse_cerberus_ssh_output(output, firmware_name)
            
            # Determine status based on version result
            if version.startswith(('SSH_', 'PARSE_', 'NOT_FOUND', 'COMMAND_FAILED')):
                status = 'error'
                error = version
                version = 'ERROR'
            else:
                status = 'success'
                error = None
                
            return {
                'version': version,
                'status': status,
                'error': error,
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_cerberus',
                'raw_output': output
            }
                
        except paramiko.AuthenticationException:
            logger.error(f"SSH authentication failed for {firmware_name} check on {rscm_ip}")
            return {
                'version': 'SSH_AUTH_FAILED',
                'status': 'error',
                'error': 'SSH authentication failed',
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_cerberus'
            }
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error for {firmware_name} check: {str(e)}")
            return {
                'version': 'SSH_CONNECTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_cerberus'
            }
        except Exception as e:
            logger.error(f"Error getting {firmware_name} version: {str(e)}")
            return {
                'version': 'EXCEPTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_cerberus'
            }
    
    def _parse_cerberus_ssh_output(self, output, firmware_name):
        """Parse Cerberus SSH command output to extract firmware version
        
        Args:
            output: Raw output from SSH Cerberus command
            firmware_name: Name of firmware for logging purposes
            
        Returns:
            Version string or error message
        """
        try:
            # Multiple regex patterns based on the PowerShell function
            
            # Pattern 1: Look for FirmwareVersion line directly
            firmware_match = re.search(r'FirmwareVersion\s*:\s*(\S+)', output)
            if firmware_match:
                version = firmware_match.group(1).strip()
                logger.debug(f"Found {firmware_name} version (pattern 1): {version}")
                return version
            
            # Pattern 2: Look for firmware/version with colon format (case insensitive)
            version_match = re.search(r'(?:firmware|version)[^\d:]*:\s*(\d+\.\d+\.\d+\.\d+)', output, re.IGNORECASE)
            if version_match:
                version = version_match.group(1).strip()
                logger.debug(f"Found {firmware_name} version (pattern 2): {version}")
                return version
            
            # Pattern 3: Look for any version-like string (format: numbers separated by dots)
            general_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', output)
            if general_match:
                version = general_match.group(1).strip()
                logger.debug(f"Found {firmware_name} version (pattern 3): {version}")
                return version
            
            # Check if the command completed successfully
            success = re.search(r'Completion\s+Code\s*:\s*Success', output)
            if not success:
                logger.warning(f"{firmware_name} command did not complete successfully")
                return 'COMMAND_FAILED'
            
            logger.warning(f"Could not parse {firmware_name} version from output: {output}")
            return 'NOT_FOUND'
            
        except Exception as e:
            logger.error(f"Error parsing {firmware_name} output: {str(e)}")
            return 'PARSE_ERROR'
    
    def _execute_ssh_ipmi_command(self, rscm_ip, system_port, component):
        """Execute SSH-based IPMI command to get firmware version
        
        Args:
            rscm_ip: RSCM IP address
            system_port: System port/slot number (used as -i parameter in IPMI command)
            component: Component type (SDRGen, FanTable, Inventory, PowerCapping)
        
        Returns:
            Version string or error message
        """
        try:
            # Map component to IPMI command code (matches PowerShell function)
            command_codes = {
                'SDRGen': '0x6',        # SDR Generator
                'FanTable': '0x4',      # Fan Table  
                'Inventory': '0x1',     # Inventory
                'PowerCapping': '0x3'   # Power Capping
            }
            
            if component not in command_codes:
                return 'INVALID_COMPONENT'
            
            command_code = command_codes[component]
            command = f"set system cmd -i {system_port} -c raw 0x36 0xd2 {command_code} 0x1"
            
            logger.debug(f"Executing SSH IPMI command: {command}")
            
            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect using SSH (typically port 22)
            ssh.connect(
                hostname=rscm_ip,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                port=22  # SSH port is always 22, not the system_port
            )
            
            # Execute the command
            stdin, stdout, stderr = ssh.exec_command(command, timeout=30)
            
            # Get the output
            output = stdout.read().decode('utf-8')
            error_output = stderr.read().decode('utf-8')
            exit_status = stdout.channel.recv_exit_status()
            
            # Close SSH connection
            ssh.close()
            
            if exit_status == 0:
                logger.debug(f"SSH command executed successfully, output: {output}")
                return self._parse_ipmi_response(output, component)
            else:
                logger.error(f"SSH command failed with exit status {exit_status}, error: {error_output}")
                return 'SSH_COMMAND_FAILED'
                
        except paramiko.AuthenticationException:
            logger.error(f"SSH authentication failed for {rscm_ip}")
            return 'SSH_AUTH_FAILED'
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error: {str(e)}")
            return 'SSH_CONNECTION_ERROR'
        except Exception as e:
            logger.error(f"Error executing SSH IPMI command: {str(e)}")
            return 'SSH_ERROR'
    
    def _parse_ipmi_response(self, output, component):
        """Parse IPMI response to extract version information
        
        Args:
            output: Raw output from SSH IPMI command
            component: Component type for logging purposes
            
        Returns:
            Version string in X.Y.Z format or error message
        """
        try:
            # Look for "Ipmi Response: " followed by hex values
            # Using regex to match the pattern from PowerShell code
            version_match = re.search(r'Ipmi Response: ([0-9A-Fa-f\s]+)(?![0-9A-Fa-f\s]*Ipmi Response)', output)
            
            if version_match:
                hex_values = version_match.group(1).strip().split()
                
                if len(hex_values) >= 3:
                    # Take the last 3 hex values and convert to decimal
                    last_three_hex = hex_values[-3:]
                    decimal_values = [str(int(hex_val, 16)) for hex_val in last_three_hex]
                    version = '.'.join(decimal_values)
                    
                    logger.debug(f"Parsed {component} version: {version} from hex values: {last_three_hex}")
                    return version
                else:
                    logger.warning(f"Not enough hex values in IPMI response for {component}: {hex_values}")
                    return 'INSUFFICIENT_DATA'
            else:
                logger.warning(f"Could not find IPMI response pattern in output for {component}")
                logger.debug(f"Raw output: {output}")
                return 'PARSE_ERROR'
                
        except Exception as e:
            logger.error(f"Error parsing IPMI response for {component}: {str(e)}")
            return 'PARSE_ERROR'
    
    def _get_bmc_config_version(self, rscm_ip, system_port, component):
        """Get BMC configuration version for a specific component using SSH IPMI
        
        Args:
            rscm_ip: RSCM IP address
            system_port: System port/slot number
            component: Component type (SDRGen, FanTable, Inventory, PowerCapping)
            
        Returns:
            Dictionary with version information
        """
        try:
            version = self._execute_ssh_ipmi_command(rscm_ip, system_port, component)
            
            # Determine status based on version result
            if version.startswith(('SSH_', 'PARSE_', 'INVALID_', 'INSUFFICIENT_')):
                status = 'error'
                error = version
                version = 'ERROR'
            else:
                status = 'success'
                error = None
                
            return {
                'version': version,
                'status': status,
                'error': error,
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_ipmi'
            }
            
        except Exception as e:
            logger.error(f"Error getting {component} version: {str(e)}")
            return {
                'version': 'EXCEPTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_ipmi'
            }
    

    def _check_firmware_placeholder(self, firmware_type, rscm_ip, system_port):
        """Placeholder function for individual firmware checks"""
        return {
            'version': 'PLACEHOLDER_VERSION',
            'status': 'not_implemented',
            'error': None,
            'checked_at': datetime.now().isoformat()
        }
    
    def check_ifwi(self, rscm_ip, rscm_port=22):
        """Check IFWI (Intel Firmware Interface) version"""
        # TODO: Implement actual IFWI checking logic
        # This will likely involve SSH connection and running specific commands
        pass
    
    def check_bmc(self, rscm_ip, rscm_port=22):
        """Check BMC (Baseboard Management Controller) version"""
        # TODO: Implement actual BMC checking logic
        pass
    
    def check_inventory(self, rscm_ip, rscm_port=22):
        """Check system inventory version"""
        # TODO: Implement actual inventory checking logic
        pass
    
    def check_power_capping(self, rscm_ip, rscm_port=22):
        """Check power capping configuration version"""
        # TODO: Implement actual power capping checking logic
        pass
    
    def check_fan_table(self, rscm_ip, rscm_port=22):
        """Check fan table version"""
        # TODO: Implement actual fan table checking logic
        pass
    
    def check_sdr_generator(self, rscm_ip, rscm_port=22):
        """Check SDR Generator version"""
        # TODO: Implement actual SDR generator checking logic
        pass
    
    def check_ipmi_allowlist(self, rscm_ip, rscm_port=22):
        """Check IPMI Allow List version"""
        # TODO: Implement actual IPMI allow list checking logic
        pass
    
    def check_bmc_tip(self, rscm_ip, rscm_port=22):
        """Check BMC Tip version"""
        # TODO: Implement actual BMC Tip checking logic
        pass
    
    def check_bmc_tip_pcd_platform_id(self, rscm_ip, rscm_port=22):
        """Check BMC Tip PCD Platform ID"""
        # TODO: Implement actual BMC Tip PCD Platform ID checking logic
        pass
    
    def check_bmc_tip_pcd_version(self, rscm_ip, rscm_port=22):
        """Check BMC Tip PCD Version"""
        # TODO: Implement actual BMC Tip PCD Version checking logic
        pass
    
    def check_manticore(self, rscm_ip, rscm_port=22):
        """Check Manticore firmware version"""
        # TODO: Implement actual Manticore checking logic
        pass
    
    def check_cfm_platform_id(self, rscm_ip, system_port=5, rscm_port=22):
        """Check CFM Platform ID using SSH connection to RSCM
        
        This function connects directly to RSCM via SSH and runs:
        'show system cerberus cfm id -i <system_port>' to get the CfmActiveIdentifier value.
        
        Expected output format:
        RScmCli# show system cerberus cfm id -i 27
            Platform:
                CfmActiveIdentifier: No valid CFM found for region 0
                CfmPendingIdentifier: No valid CFM found for region 1
            Completion Code: Success
        
        Args:
            rscm_ip: RSCM IP address
            system_port: System/slot port number (default 5)
            rscm_port: SSH port (default 22)
            
        Returns:
            Dictionary with CFM Platform ID information
        """
        try:
            logger.info(f"Starting CFM Platform ID check via direct SSH to {rscm_ip}:{rscm_port}")
            print(f"[DC-SCM] CFM Platform ID: Connecting to RSCM via SSH...")
            
            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect to RSCM
            print(f"[DC-SCM] CFM Platform ID: Establishing SSH connection to {rscm_ip}...")
            ssh.connect(
                hostname=rscm_ip,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                port=rscm_port
            )
            print(f"[DC-SCM] CFM Platform ID: SSH connection established")
            
            # Create an interactive shell
            print(f"[DC-SCM] CFM Platform ID: Creating interactive shell...")
            shell = ssh.invoke_shell()
            time.sleep(2)  # Wait for shell to be ready and show prompt
            
            # Clear any initial output
            if shell.recv_ready():
                initial_output = shell.recv(8192).decode('utf-8', errors='ignore')
                logger.debug(f"Initial shell output: {repr(initial_output)}")
            
            # Send the CFM command with the correct system port
            cfm_command = f"show system cerberus cfm id -i {system_port}\n"
            logger.debug(f"[DEBUG] Sending CFM command: {cfm_command.strip()}")
            print(f"[DC-SCM] [DEBUG] Sending command: {cfm_command.strip()}")
            shell.send(cfm_command)
            
            # Wait for command execution - CFM commands can take up to 40 seconds
            # Keep reading until we see "Completion Code: Success" or "Completion Code: Failed"
            print(f"[DC-SCM] [DEBUG] Waiting for CFM command to complete (up to 40 seconds)...")
            cfm_output = ""
            start_time = time.time()
            max_wait = 40
            last_output_time = start_time
            no_output_timeout = 5  # If no output for 5 seconds after getting some data, consider it done
            
            while time.time() - start_time < max_wait:
                # Read any available output
                if shell.recv_ready():
                    chunk = shell.recv(8192).decode('utf-8', errors='ignore')
                    if chunk:
                        cfm_output += chunk
                        last_output_time = time.time()
                        logger.debug(f"[DEBUG] Received chunk: {len(chunk)} chars, total: {len(cfm_output)}")
                        print(f"[DC-SCM] [DEBUG] Received {len(chunk)} chars, total: {len(cfm_output)} chars")
                
                # Check if we've received the completion indicator (Success or Failed)
                if "Completion Code: Success" in cfm_output or "Completion Code: Failed" in cfm_output:
                    elapsed = time.time() - start_time
                    print(f"[DC-SCM] [DEBUG] Command completed after {elapsed:.1f} seconds")
                    logger.debug(f"[DEBUG] Found 'Completion Code' after {elapsed:.1f}s")
                    # Wait a bit more to ensure all output is received
                    time.sleep(0.5)
                    if shell.recv_ready():
                        final_chunk = shell.recv(8192).decode('utf-8', errors='ignore')
                        if final_chunk:
                            cfm_output += final_chunk
                            print(f"[DC-SCM] [DEBUG] Received final {len(final_chunk)} chars")
                    break
                
                # If we have some output and no new data for timeout period, something might be wrong
                if cfm_output and (time.time() - last_output_time > no_output_timeout):
                    elapsed = time.time() - start_time
                    print(f"[DC-SCM] [WARNING] No new output for {no_output_timeout}s after {elapsed:.1f}s total")
                    logger.warning(f"No new output for {no_output_timeout}s, checking if command stalled")
                    # Continue waiting up to max_wait, don't break yet
                
                # Small sleep to avoid tight loop
                time.sleep(0.2)
            
            if "Completion Code: Success" not in cfm_output and "Completion Code: Failed" not in cfm_output:
                print(f"[DC-SCM] [WARNING] Command did not complete within {max_wait} seconds")
                logger.warning(f"CFM command timed out after {max_wait}s without seeing Completion Code")
            
            logger.debug(f"[DEBUG] CFM Platform ID raw output length: {len(cfm_output)} chars")
            logger.debug(f"[DEBUG] Raw output: {repr(cfm_output)}")
            print(f"[DC-SCM] [DEBUG] Final output: {len(cfm_output)} characters")
            
            # Close connections
            print(f"[DC-SCM] [DEBUG] Closing SSH connections...")
            shell.close()
            ssh.close()
            
            # Parse the CfmActiveIdentifier from output
            print(f"[DC-SCM] [DEBUG] Starting to parse CFM Platform ID...")
            cfm_active_id = self._parse_cfm_active_identifier(cfm_output)
            
            # Check if we got a valid response from RSCM (even if CFM failed)
            # If we see "Completion Code" in output, RSCM responded successfully
            has_completion_code = "Completion Code" in cfm_output
            
            if cfm_active_id:
                # We found CfmActiveIdentifier - could be a value, "No valid CFM", or "failed to get"
                logger.info(f"Successfully retrieved CFM Platform ID response: {cfm_active_id}")
                return {
                    'version': cfm_active_id,
                    'status': 'success',
                    'error': None,
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_direct_rscm_cfm_command',
                    'raw_output': cfm_output
                }
            elif has_completion_code:
                # RSCM responded but we couldn't parse CfmActiveIdentifier
                # This shouldn't normally happen, but if it does, still mark as success since RSCM responded
                logger.warning("RSCM responded with Completion Code but could not parse CfmActiveIdentifier")
                return {
                    'version': 'PARSE_ERROR_BUT_RSCM_RESPONDED',
                    'status': 'success',
                    'error': None,
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_direct_rscm_cfm_command',
                    'raw_output': cfm_output,
                    'note': 'RSCM responded successfully but CfmActiveIdentifier could not be parsed from output'
                }
            else:
                # No CfmActiveIdentifier and no Completion Code - command likely failed or timed out
                logger.warning("Could not parse CFM Platform ID from output and no Completion Code found")
                return {
                    'version': 'CFM_COMMAND_FAILED',
                    'status': 'error',
                    'error': 'Could not find CfmActiveIdentifier or Completion Code in command output',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_direct_rscm_cfm_command',
                    'raw_output': cfm_output
                }
                
        except paramiko.AuthenticationException:
            logger.error(f"SSH authentication failed for CFM Platform ID check on {rscm_ip}")
            return {
                'version': 'SSH_AUTH_FAILED',
                'status': 'error',
                'error': 'SSH authentication failed',
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_direct_rscm_cfm_command'
            }
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error for CFM Platform ID check: {str(e)}")
            return {
                'version': 'SSH_CONNECTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_direct_rscm_cfm_command'
            }
        except Exception as e:
            logger.error(f"Error checking CFM Platform ID: {str(e)}")
            return {
                'version': 'EXCEPTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_direct_rscm_cfm_command'
            }
    
    def check_cfm_version_id(self, rscm_ip, rscm_port=22):
        """Check CFM Version ID"""
        # TODO: Implement actual CFM Version ID checking logic
        pass
    
    def check_tpm_module(self, rscm_ip, rscm_port=22):
        """Check TPM Module version"""
        # TODO: Implement actual TPM module checking logic
        pass
    
    def check_scm_cpld(self, rscm_ip, rscm_port=22):
        """Check SCM-CPLD version"""
        # TODO: Implement actual SCM-CPLD checking logic
        pass
    
    def check_individual_firmware(self, firmware_type, rscm_ip, system_port=5):
        """Check individual firmware type with detailed progress
        
        Args:
            firmware_type: Name of the firmware type to check
            rscm_ip: RSCM IP address
            system_port: System port/slot number
            
        Returns:
            Dictionary with firmware version information
        """
        print(f"[DC-SCM] Checking individual firmware: {firmware_type}")
        
        try:
            # Map firmware types to their checking methods
            if firmware_type == 'IFWI':
                return self._check_ifwi_individual(rscm_ip, system_port)
            elif firmware_type == 'BMC FW':
                return self._check_bmc_individual(rscm_ip, system_port)
            elif firmware_type == 'SCM-CPLD':
                return self._check_scm_cpld_individual(rscm_ip, system_port)
            elif firmware_type in ['Inventory', 'PowerCapping', 'FanTable', 'SDRGenerator']:
                return self._check_bmc_config_individual(firmware_type, rscm_ip, system_port)
            elif firmware_type == 'IPMIAllowList':
                # No command available yet for IPMIAllowList
                return {
                    'version': 'NOT_IMPLEMENTED',
                    'status': 'not_implemented',
                    'error': 'Command not yet available for IPMIAllowList checking',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'not_available'
                }
            elif firmware_type in ['BMC Tip', 'BMC TIP PCD Platform ID', 'BMC TIP PCD Version ID (hex)/(dec)']:
                return self._check_bmc_tip_individual(firmware_type, rscm_ip, system_port)
            elif firmware_type == 'CFM Platform ID':
                return self.check_cfm_platform_id(rscm_ip, system_port)
            elif firmware_type == 'CFM Version ID (hex)/(dec)':
                return {
                    'version': 'NOT_IMPLEMENTED_BY_DEV_TEAMS',
                    'status': 'not_implemented',
                    'error': 'CFM Version ID checking not yet implemented by development teams',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'not_available'
                }
            elif firmware_type == 'Manticore (HSM)':
                return self._check_cerberus_individual(firmware_type, rscm_ip, system_port)
            elif firmware_type == 'TPM Module':
                return self._check_tpm_individual(rscm_ip, system_port)
            elif firmware_type == 'UEFI Profile/Other':
                return self._check_uefi_individual(rscm_ip, system_port)
            else:
                return self._check_firmware_placeholder(firmware_type, rscm_ip, system_port)
        
        except Exception as e:
            logger.error(f"Error checking individual DC-SCM firmware {firmware_type}: {str(e)}")
            return {
                'version': 'EXCEPTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'individual_check'
            }
    
    def _check_ifwi_individual(self, rscm_ip, system_port):
        """Check IFWI using Redfish API"""
        try:
            system_data = self._get_redfish_data(rscm_ip, system_port, self.base_endpoints['system'])
            if system_data:
                return self._extract_bios_version(system_data)
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
    
    def _check_bmc_individual(self, rscm_ip, system_port):
        """Check BMC FW using Redfish API"""
        try:
            system_data = self._get_redfish_data(rscm_ip, system_port, self.base_endpoints['system'])
            if system_data:
                return self._extract_bmc_version(system_data)
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
    
    def _check_scm_cpld_individual(self, rscm_ip, system_port):
        """Check SCM-CPLD using Redfish API"""
        try:
            system_data = self._get_redfish_data(rscm_ip, system_port, self.base_endpoints['system'])
            if system_data:
                return self._extract_scm_cpld_version(system_data)
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
    
    def _check_bmc_config_individual(self, firmware_type, rscm_ip, system_port):
        """Check BMC configuration items using SSH IPMI commands"""
        print(f"[DC-SCM] Checking BMC config: {firmware_type} via SSH IPMI...")
        try:
            return self._get_bmc_config_via_ssh(firmware_type, rscm_ip, system_port)
        except Exception as e:
            return {
                'version': 'SSH_IPMI_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_ipmi'
            }
    
    def _check_bmc_tip_individual(self, firmware_type, rscm_ip, system_port):
        """Check BMC TIP items using SSH IPMI commands"""
        print(f"[DC-SCM] Checking BMC TIP: {firmware_type} via SSH IPMI...")
        try:
            return self._get_bmc_tip_via_ssh(firmware_type, rscm_ip, system_port)
        except Exception as e:
            return {
                'version': 'SSH_IPMI_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_ipmi'
            }
    
    def _check_cerberus_individual(self, firmware_type, rscm_ip, system_port):
        """Check Cerberus items - use Redfish for Manticore, SSH for others"""
        print(f"[DC-SCM] Checking Cerberus: {firmware_type}...")
        try:
            # For Manticore (HSM), use Redfish endpoint instead of SSH command
            # SSH exec_command doesn't handle the long-running Cerberus commands well
            if firmware_type == 'Manticore (HSM)':
                print(f"[DC-SCM] Using Redfish API for {firmware_type}...")
                cerberus_data = self._get_redfish_data(rscm_ip, system_port, '/redfish/v1/System/Cerberus/1')
                if cerberus_data:
                    return self._extract_cerberus_version(cerberus_data)
                else:
                    return {
                        'version': 'CONNECTION_FAILED',
                        'status': 'error',
                        'error': 'Failed to connect to Cerberus Redfish endpoint',
                        'checked_at': datetime.now().isoformat(),
                        'method': 'redfish_api'
                    }
            else:
                # For other Cerberus items, use SSH commands
                print(f"[DC-SCM] Using SSH Cerberus command for {firmware_type}...")
                return self._get_cerberus_info_via_ssh(firmware_type, rscm_ip, system_port)
        except Exception as e:
            return {
                'version': 'CERBERUS_CHECK_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'cerberus_check'
            }
    
    def _check_tpm_individual(self, rscm_ip, system_port):
        """Check TPM Module using available method"""
        print(f"[DC-SCM] Checking TPM Module...")
        try:
            # Try Redfish first, then fall back to placeholder
            system_data = self._get_redfish_data(rscm_ip, system_port, self.base_endpoints['system'])
            if system_data:
                # Extract TPM info if available in system data
                return {
                    'version': 'NOT_IMPLEMENTED',
                    'status': 'not_implemented',
                    'error': 'TPM module info not available via Redfish',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'redfish_api'
                }
            else:
                return self._check_firmware_placeholder('TPM Module', rscm_ip, system_port)
        except Exception as e:
            return {
                'version': 'EXCEPTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'multiple'
            }
    
    def _check_uefi_individual(self, rscm_ip, system_port):
        """Check UEFI Profile/Other using BIOS config parsing"""
        print(f"[DC-SCM] Checking UEFI Profile/Other via BIOS config...")
        try:
            # Get BIOS config data
            bios_config = self._get_redfish_data(rscm_ip, system_port, self.base_endpoints['biosconfig'])
            if bios_config:
                print(f"[DC-SCM DEBUG] Retrieved BIOS config data for UEFI parsing")
                
                # Extract BIOS configuration information
                current_config = bios_config.get('CurrentConfiguration', '').strip()
                available_configs = bios_config.get('AvailableConfigurations', [])
                
                print(f"[DC-SCM DEBUG] BIOS Current Configuration: {current_config}")
                print(f"[DC-SCM DEBUG] BIOS Available Configurations: {available_configs}")
                
                # Map current configuration value to configuration name
                config_name = self._map_bios_config_value(current_config, available_configs)
                
                # Format version string
                if config_name:
                    version = f"{config_name} ({current_config})"
                elif current_config:
                    version = current_config
                else:
                    version = 'NO_CONFIG_DATA'
                
                return {
                    'version': version,
                    'status': 'success' if version != 'NO_CONFIG_DATA' else 'error',
                    'error': None if version != 'NO_CONFIG_DATA' else 'No BIOS configuration data available',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'redfish_bios_config',
                    'raw_config': current_config,
                    'config_name': config_name
                }
            else:
                print(f"[DC-SCM DEBUG] Failed to retrieve BIOS config data")
                return {
                    'version': 'BIOS_CONFIG_UNAVAILABLE',
                    'status': 'error',
                    'error': 'Failed to retrieve BIOS configuration via Redfish',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'redfish_bios_config'
                }
                
        except Exception as e:
            print(f"[DC-SCM DEBUG] Exception during UEFI BIOS config check: {str(e)}")
            return {
                'version': 'BIOS_CONFIG_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'redfish_bios_config'
            }
    
    def _test_ssh_connection(self, rscm_ip):
        """Test basic SSH connectivity to RSCM"""
        try:
            print(f"[DC-SCM DEBUG] Testing basic SSH connectivity to {rscm_ip}:22")
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                hostname=rscm_ip,
                port=22,
                username=self.username,
                password=self.password,
                timeout=10,  # Shorter timeout for test
                banner_timeout=10,
                auth_timeout=10
            )
            
            # Try a simple command
            stdin, stdout, stderr = ssh.exec_command('echo "SSH test successful"', timeout=10)
            output = stdout.read().decode('utf-8').strip()
            ssh.close()
            
            print(f"[DC-SCM DEBUG] SSH test successful: {output}")
            return True
            
        except Exception as e:
            print(f"[DC-SCM DEBUG] SSH test failed: {str(e)}")
            return False
    
    def _get_bmc_config_via_ssh(self, firmware_type, rscm_ip, system_port):
        """Get BMC configuration via SSH IPMI commands"""
        try:
            print(f"[DC-SCM DEBUG] Starting {firmware_type} check with credentials: user='{self.username}', password={'*' * len(self.password) if self.password else 'None'}")
            
            # Test SSH connection first
            if not self._test_ssh_connection(rscm_ip):
                return {
                    'version': 'SSH_TEST_FAILED',
                    'status': 'error',
                    'error': 'Basic SSH connectivity test failed',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_ipmi'
                }
            # Map firmware types to raw IPMI commands (matching PowerShell implementation)
            raw_commands = {
                'Inventory': 'raw 0x36 0xd2 0x1 0x1',     # Component code 0x1
                'PowerCapping': 'raw 0x36 0xd2 0x3 0x1',  # Component code 0x3  
                'FanTable': 'raw 0x36 0xd2 0x4 0x1',      # Component code 0x4
                'SDRGenerator': 'raw 0x36 0xd2 0x6 0x1'   # Component code 0x6
            }
            
            if firmware_type not in raw_commands:
                return {
                    'version': 'COMMAND_NOT_AVAILABLE',
                    'status': 'not_implemented',
                    'error': f'No raw IPMI command available for {firmware_type}',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_ipmi'
                }
            
            command = raw_commands[firmware_type]
            
            # Execute SSH IPMI command
            print(f"[DC-SCM DEBUG] Attempting SSH connection to {rscm_ip}:22 with user '{self.username}' (timeout={self.timeout}s)")
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                ssh.connect(
                    hostname=rscm_ip,
                    port=22,
                    username=self.username,
                    password=self.password,
                    timeout=self.timeout,
                    banner_timeout=30,  # Add banner timeout
                    auth_timeout=30     # Add auth timeout
                )
                print(f"[DC-SCM DEBUG] SSH connection successful to {rscm_ip}")
            except Exception as ssh_error:
                print(f"[DC-SCM DEBUG] SSH connection failed to {rscm_ip}: {str(ssh_error)}")
                raise ssh_error
            
            # Execute command directly on RSCM CLI (matching your PuTTY session)
            rscm_command = f'set system cmd -i {system_port} -c {command}'
            print(f"[DC-SCM DEBUG] Executing RSCM command for {firmware_type}: {rscm_command}")
            
            stdin, stdout, stderr = ssh.exec_command(rscm_command)
            
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            print(f"[DC-SCM DEBUG] IPMI Response for {firmware_type}:")
            print(f"[DC-SCM DEBUG] STDOUT: {repr(output)}")
            print(f"[DC-SCM DEBUG] STDERR: {repr(error)}")
            
            ssh.close()
            
            if error and 'error' in error.lower():
                return {
                    'version': f'IPMI_ERROR: {error.strip()[:50]}',
                    'status': 'error',
                    'error': error.strip(),
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_ipmi'
                }
            
            # Parse output for version info
            version = self._parse_ipmi_output(firmware_type, output)
            
            # Determine status based on parsed result
            if any(error_prefix in version for error_prefix in ['NO_OUTPUT', 'HEX_PARSE_ERROR', 'NO_IPMI_RESPONSE_PATTERN_FOUND', 'INSUFFICIENT_HEX_VALUES', 'UNPARSED_OUTPUT']):
                status = 'error'
            elif version and not version.startswith(('ERROR:', 'PARSED_FROM_IPMI:')):
                status = 'success'
            else:
                status = 'error'
            
            return {
                'version': version,
                'status': status,
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_ipmi'
            }
            
        except paramiko.AuthenticationException as auth_error:
            print(f"[DC-SCM DEBUG] SSH authentication failed for {firmware_type}: {str(auth_error)}")
            logger.error(f"SSH authentication failed for {firmware_type}: {str(auth_error)}")
            return {
                'version': f'SSH_AUTH_FAILED',
                'status': 'error',
                'error': f'SSH authentication failed: {str(auth_error)}',
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_ipmi'
            }
        except paramiko.SSHException as ssh_error:
            print(f"[DC-SCM DEBUG] SSH connection error for {firmware_type}: {str(ssh_error)}")
            logger.error(f"SSH connection error for {firmware_type}: {str(ssh_error)}")
            return {
                'version': f'SSH_CONNECTION_ERROR',
                'status': 'error',
                'error': f'SSH connection failed: {str(ssh_error)}',
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_ipmi'
            }
        except Exception as e:
            print(f"[DC-SCM DEBUG] General error for {firmware_type}: {str(e)}")
            logger.error(f"SSH IPMI error for {firmware_type}: {str(e)}")
            return {
                'version': f'SSH_ERROR: {str(e)[:50]}',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_ipmi'
            }
    
    def _get_bmc_tip_via_ssh(self, firmware_type, rscm_ip, system_port):
        """Get BMC TIP info via SSH Cerberus commands (matching PowerShell implementation)"""
        try:
            # Handle not-implemented firmware types first
            if firmware_type in ['BMC TIP PCD Platform ID', 'BMC TIP PCD Version ID (hex)/(dec)']:
                print(f"[DC-SCM DEBUG] {firmware_type} is not yet implemented by development teams")
                return {
                    'version': 'NOT IMPLEMENTED',
                    'status': 'not_implemented',
                    'error': 'Command not yet implemented by development teams',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'not_available'
                }
            
            # Map firmware types to Cerberus commands (matching PowerShell)
            cerberus_commands = {
                'BMC Tip': f'show system cerberus version -i {system_port} -t 0 -b 0 -c 2'  # Component code 2 for TIP
            }
            
            # Only BMC Tip should reach this point
            if firmware_type != 'BMC Tip':
                return {
                    'version': 'UNKNOWN_FIRMWARE_TYPE',
                    'status': 'error',
                    'error': f'Unknown firmware type: {firmware_type}',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'unknown'
                }
            
            command = cerberus_commands[firmware_type]
            print(f"[DC-SCM DEBUG] Executing BMC TIP command for {firmware_type}: {command}")
            
            # Execute SSH command for BMC Tip only
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                hostname=rscm_ip,
                port=22,
                username=self.username,
                password=self.password,
                timeout=self.timeout
            )
            
            # Use Cerberus command for BMC Tip (like Manticore)
            stdin, stdout, stderr = ssh.exec_command(command)
            
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            print(f"[DC-SCM DEBUG] BMC TIP Cerberus Response for {firmware_type}:")
            print(f"[DC-SCM DEBUG] STDOUT: {repr(output)}")
            print(f"[DC-SCM DEBUG] STDERR: {repr(error)}")
            
            ssh.close()
            
            if error and 'error' in error.lower():
                return {
                    'version': f'CERBERUS_ERROR: {error.strip()[:50]}',
                    'status': 'error',
                    'error': error.strip(),
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_cerberus'
                }
            
            # Parse Cerberus output for BMC Tip
            version = self._parse_bmc_tip_cerberus_output(output)
            
            # Determine status based on parsed result
            if version.startswith(('NOT_FOUND', 'PARSE_ERROR', 'NO_OUTPUT', 'COMMAND_FAILED')):
                status = 'error'
            elif version and not version.startswith('ERROR:'):
                status = 'success'
            else:
                status = 'error'
            
            return {
                'version': version,
                'status': status,
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_cerberus'
            }
            
        except Exception as e:
            logger.error(f"SSH BMC TIP error for {firmware_type}: {str(e)}")
            return {
                'version': f'SSH_TIP_ERROR: {str(e)[:50]}',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_cerberus'
            }
    
    def _get_cerberus_info_via_ssh(self, firmware_type, rscm_ip, system_port):
        """Get Cerberus info via SSH commands (matching PowerShell implementation)"""
        try:
            # Map firmware types to Cerberus commands (matching PowerShell)
            cerberus_commands = {
                'Manticore (HSM)': f'show system cerberus version -i {system_port} -t 0 -b 0 -c 1',  # Component code 1 for Manticore
                'CFM Platform ID': 'cerberus_utility get_cfm_id -i 2',
                'CFM Version ID (hex)/(dec)': 'cerberus_utility get_cfm_id -i 2'
            }
            
            command = cerberus_commands.get(firmware_type, 'cerberus_utility get_device_info -i 2')
            
            print(f"[DC-SCM DEBUG] Executing Cerberus command for {firmware_type}: {command}")
            
            # Execute SSH Cerberus command
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                hostname=rscm_ip,
                port=22,
                username=self.username,
                password=self.password,
                timeout=self.timeout
            )
            
            # Execute Cerberus command
            stdin, stdout, stderr = ssh.exec_command(command)
            
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            print(f"[DC-SCM DEBUG] Cerberus Response for {firmware_type}:")
            print(f"[DC-SCM DEBUG] STDOUT: {repr(output)}")
            print(f"[DC-SCM DEBUG] STDERR: {repr(error)}")
            
            ssh.close()
            
            if error and 'error' in error.lower():
                return {
                    'version': f'CERBERUS_ERROR: {error.strip()[:50]}',
                    'status': 'error',
                    'error': error.strip(),
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_cerberus'
                }
            
            # Parse Cerberus output
            version = self._parse_cerberus_output(firmware_type, output)
            
            # Determine status based on parsed result
            if version.startswith(('NOT_FOUND', 'PARSE_ERROR', 'NO_CERBERUS_OUTPUT', 'COMMAND_FAILED')):
                status = 'error'
            elif version and not version.startswith('ERROR:'):
                status = 'success'
            else:
                status = 'error'
            
            return {
                'version': version,
                'status': status,
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_cerberus'
            }
            
        except Exception as e:
            logger.error(f"SSH Cerberus error for {firmware_type}: {str(e)}")
            return {
                'version': f'SSH_CERBERUS_ERROR: {str(e)[:50]}',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_cerberus'
            }
    
    def _parse_ipmi_output(self, firmware_type, output):
        """Parse IPMI command output to extract version info (matching PowerShell implementation)"""
        if not output:
            return 'NO_OUTPUT'
        
        # Parse raw IPMI responses for specific firmware types
        if firmware_type in ['Inventory', 'PowerCapping', 'FanTable', 'SDRGenerator']:
            import re
            print(f"[DC-SCM DEBUG] Parsing {firmware_type} output: {repr(output)}")
            
            # Look for "Ipmi Response: [hex values]" pattern (matching PowerShell regex)
            version_match = re.search(r'Ipmi Response:\s*([0-9A-Fa-f\s]+)(?![0-9A-Fa-f\s]*Ipmi Response)', output)
            
            if version_match:
                # Extract hex values and get last 3 (matching PowerShell logic)
                hex_string = version_match.group(1).strip()
                hex_values = hex_string.split()
                print(f"[DC-SCM DEBUG] Found hex values: {hex_values}")
                
                if len(hex_values) >= 3:
                    # Take last 3 hex values and convert to decimal (matching PowerShell)
                    last_three_hex = hex_values[-3:]
                    print(f"[DC-SCM DEBUG] Last 3 hex values: {last_three_hex}")
                    try:
                        decimal_values = [str(int(hex_val, 16)) for hex_val in last_three_hex]
                        version = '.'.join(decimal_values)
                        print(f"[DC-SCM DEBUG] Converted to decimal version: {version}")
                        return version
                    except ValueError as e:
                        print(f"[DC-SCM DEBUG] Hex conversion error: {e}")
                        return f'HEX_PARSE_ERROR: {str(e)}'
                else:
                    print(f"[DC-SCM DEBUG] Not enough hex values: {len(hex_values)} found, need at least 3")
                    return f'INSUFFICIENT_HEX_VALUES: {len(hex_values)} found'
            else:
                print(f"[DC-SCM DEBUG] No 'Ipmi Response:' pattern found in output")
                return f'NO_IPMI_RESPONSE_PATTERN_FOUND'
        

        
        # Generic parsing for other types
        lines = output.strip().split('\n')
        for line in lines:
            if 'version' in line.lower() or 'rev' in line.lower():
                import re
                version_match = re.search(r'[\d]+\.[\d]+\.?[\d]*', line)
                if version_match:
                    return version_match.group()
        
        return f'UNPARSED_OUTPUT: {len(output.strip().split())} tokens'
    
    def _parse_ipmi_raw_output(self, firmware_type, output):
        """Parse IPMI raw command output"""
        if not output:
            return 'NO_RAW_OUTPUT'
        
        # Parse hex values from raw output
        hex_values = output.strip().split()
        if hex_values:
            return f'RAW_HEX: {" ".join(hex_values[:4])}'
        
        return 'NOT_PARSED'
    
    def _parse_cerberus_output(self, firmware_type, output):
        """Parse Cerberus command output (matching PowerShell implementation)"""
        if not output:
            return 'NO_CERBERUS_OUTPUT'
        
        print(f"[DC-SCM DEBUG] Parsing {firmware_type} Cerberus output: {repr(output)}")
        
        # Parse based on firmware type
        if firmware_type == 'Manticore (HSM)':
            import re
            
            # Pattern 1: Look for FirmwareVersion line directly (matching PowerShell)
            firmware_match = re.search(r'FirmwareVersion\s*:\s*(\S+)', output)
            if firmware_match:
                version = firmware_match.group(1).strip()
                print(f"[DC-SCM DEBUG] Found Manticore version (pattern 1): {version}")
                return version
            
            # Pattern 2: Look for firmware/version with colon format (case insensitive)
            version_match = re.search(r'(?:firmware|version)[^\d:]*:\s*(\d+\.\d+\.\d+\.\d+)', output, re.IGNORECASE)
            if version_match:
                version = version_match.group(1).strip()
                print(f"[DC-SCM DEBUG] Found Manticore version (pattern 2): {version}")
                return version
            
            # Pattern 3: Look for any version-like string (format: numbers separated by dots, with possible dash)
            general_match = re.search(r'(\d+\.\d+\.\d+\.\d+(?:-\d+)?)', output)
            if general_match:
                version = general_match.group(1).strip()
                print(f"[DC-SCM DEBUG] Found Manticore version (pattern 3): {version}")
                return version
            
            # Check if the command completed successfully
            success = re.search(r'Completion\s+Code\s*:\s*Success', output)
            if not success:
                print(f"[DC-SCM DEBUG] Manticore command did not complete successfully")
                return 'COMMAND_FAILED'
            
            print(f"[DC-SCM DEBUG] Could not parse Manticore version from output")
            return 'NOT_FOUND'
            
        elif firmware_type == 'CFM Platform ID':
            # Look for platform ID patterns
            import re
            # Look for hex patterns like "Platform ID: 0x12345678" or just hex values
            if 'platform' in output.lower() and 'id' in output.lower():
                hex_match = re.search(r'0x([0-9a-fA-F]+)', output)
                if hex_match:
                    return f'0x{hex_match.group(1).upper()}'
                # Look for decimal ID
                dec_match = re.search(r'(\d+)', output)
                if dec_match:
                    return dec_match.group(1)
            # Direct hex value lines
            hex_match = re.search(r'^0x([0-9a-fA-F]+)', output.strip())
            if hex_match:
                return f'0x{hex_match.group(1).upper()}'
            # Look for 4-byte hex patterns
            four_byte_match = re.search(r'([0-9a-fA-F]{8})', output)
            if four_byte_match:
                return f'0x{four_byte_match.group(1).upper()}'
            
        elif firmware_type == 'CFM Version ID (hex)/(dec)':
            import re
            # Look for version patterns
            if 'version' in output.lower() and 'id' in output.lower():
                hex_match = re.search(r'0x([0-9a-fA-F]+)', output)
                if hex_match:
                    hex_val = hex_match.group(1).upper()
                    try:
                        dec_val = int(hex_val, 16)
                        return f'0x{hex_val} ({dec_val})'
                    except ValueError:
                        return f'0x{hex_val}'
            # Direct hex value lines
            hex_match = re.search(r'^0x([0-9a-fA-F]+)', output.strip())
            if hex_match:
                hex_val = hex_match.group(1).upper()
                try:
                    dec_val = int(hex_val, 16)
                    return f'0x{hex_val} ({dec_val})'
                except ValueError:
                    return f'0x{hex_val}'
            # Look for 4-byte hex patterns
            four_byte_match = re.search(r'([0-9a-fA-F]{8})', output)
            if four_byte_match:
                hex_val = four_byte_match.group(1).upper()
                try:
                    dec_val = int(hex_val, 16)
                    return f'0x{hex_val} ({dec_val})'
                except ValueError:
                    return f'0x{hex_val}'
        
        # Generic parsing for other Cerberus commands
        lines = output.strip().split('\n')
        for line in lines:
            if 'id' in line.lower() or 'version' in line.lower():
                # Extract ID or version info
                parts = line.split(':')
                if len(parts) > 1:
                    return parts[1].strip()
        
        return f'PARSE_ERROR: Could not extract version from {len(lines)} lines'
    
    def _parse_bmc_tip_cerberus_output(self, output):
        """Parse BMC TIP Cerberus command output (matching PowerShell implementation)"""
        if not output:
            return 'NO_OUTPUT'
        
        print(f"[DC-SCM DEBUG] Parsing BMC TIP Cerberus output: {repr(output)}")
        
        import re
        
        # Pattern 1: Look for FirmwareVersion line directly (matching PowerShell)
        firmware_match = re.search(r'FirmwareVersion\s*:\s*(\S+)', output)
        if firmware_match:
            version = firmware_match.group(1).strip()
            print(f"[DC-SCM DEBUG] Found BMC TIP version (pattern 1): {version}")
            return version
        
        # Pattern 2: Look for firmware/version with colon format (case insensitive)
        version_match = re.search(r'(?:firmware|version)[^\d:]*:\s*(\d+\.\d+\.\d+\.\d+)', output, re.IGNORECASE)
        if version_match:
            version = version_match.group(1).strip()
            print(f"[DC-SCM DEBUG] Found BMC TIP version (pattern 2): {version}")
            return version
        
        # Pattern 3: Look for any version-like string (format: numbers separated by dots)
        general_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', output)
        if general_match:
            version = general_match.group(1).strip()
            print(f"[DC-SCM DEBUG] Found BMC TIP version (pattern 3): {version}")
            return version
        
        # Check if the command completed successfully
        success = re.search(r'Completion\s+Code\s*:\s*Success', output)
        if not success:
            print(f"[DC-SCM DEBUG] BMC TIP command did not complete successfully")
            return 'COMMAND_FAILED'
        
        print(f"[DC-SCM DEBUG] Could not parse BMC TIP version from output")
        return 'NOT_FOUND'
    
    def _read_shell_output(self, shell, timeout=30):
        """Read output from SSH shell with timeout
        
        Args:
            shell: Paramiko shell channel
            timeout: Maximum time to wait for output
            
        Returns:
            String containing all available output
        """
        output = ""
        start_time = time.time()
        last_data_time = start_time
        no_data_threshold = 3  # Consider done if no data for 3 seconds (reduced from 10)
        
        logger.debug(f"Starting to read shell output (timeout: {timeout}s)")
        print(f"[DC-SCM] Reading shell output (timeout: {timeout}s)...")
        
        while time.time() - start_time < timeout:
            if shell.recv_ready():
                try:
                    chunk = shell.recv(8192).decode('utf-8', errors='ignore')
                    if chunk:
                        output += chunk
                        last_data_time = time.time()
                        logger.debug(f"Received {len(chunk)} chars, total: {len(output)}")
                        print(f"[DC-SCM] [DEBUG] Received chunk: {len(chunk)} chars, total: {len(output)} chars")
                except Exception as e:
                    logger.warning(f"Error reading shell chunk: {e}")
                    break
            else:
                # If no data available, wait a bit
                time.sleep(0.2)
                
                # If we have received some data and no new data for threshold seconds, consider done
                if output and (time.time() - last_data_time > no_data_threshold):
                    logger.debug(f"No data received for {no_data_threshold} seconds after getting output, considering complete")
                    print(f"[DC-SCM] [DEBUG] Output appears complete ({len(output)} chars)")
                    break
                
        logger.debug(f"Finished reading shell output: {len(output)} characters")
        return output
    
    def _parse_cfm_active_identifier(self, output):
        """Parse CfmActiveIdentifier from 'show system cerberus cfm id -i 4' output
        
        Expected format:
        RScmCli# show system cerberus cfm id -i 4
            Platform:
                CfmActiveIdentifier: No valid CFM found for region 0
                CfmPendingIdentifier: No valid CFM found for region 1
            Completion Code: Success
        
        Args:
            output: Raw output from 'show system cerberus cfm id -i 4' command
            
        Returns:
            CfmActiveIdentifier value or None if not found
        """
        try:
            import re
            
            logger.debug(f"[DEBUG] Raw CFM command output length: {len(output)} chars")
            logger.debug(f"[DEBUG] Raw output preview (first 500 chars): {repr(output[:500])}")
            print(f"[DC-SCM] [DEBUG] Parsing CFM output, length: {len(output)} chars")
            
            # Normalize line endings and split into lines
            output = output.replace('\r\n', '\n').replace('\r', '\n')
            lines = output.split('\n')
            
            logger.debug(f"[DEBUG] Split into {len(lines)} lines")
            print(f"[DC-SCM] [DEBUG] Split into {len(lines)} lines for parsing")
            
            # Debug: Print each line with line number
            for i, line in enumerate(lines):
                line_clean = line.strip()
                if line_clean:  # Only log non-empty lines
                    logger.debug(f"[DEBUG] Line {i:2d}: '{line_clean}'")
                    print(f"[DC-SCM] [DEBUG] Line {i:2d}: '{line_clean}'")
            
            # Look for "CfmActiveIdentifier:" line
            for i, line in enumerate(lines):
                line = line.strip()
                
                # Pattern to match CfmActiveIdentifier line
                cfm_match = re.match(r'^\s*CfmActiveIdentifier\s*:\s*(.+)$', line, re.IGNORECASE)
                if cfm_match:
                    cfm_value = cfm_match.group(1).strip()
                    logger.debug(f"[DEBUG] FOUND! CfmActiveIdentifier on line {i}: '{line}'")
                    logger.debug(f"[DEBUG] Extracted CFM value: '{cfm_value}'")
                    print(f"[DC-SCM] [DEBUG] SUCCESS! Found CFM Platform ID: '{cfm_value}' on line {i}")
                    return cfm_value
            
            # If we get here, no CfmActiveIdentifier was found
            logger.warning("[DEBUG] CfmActiveIdentifier not found in any line")
            logger.warning(f"[DEBUG] Full output for analysis: {repr(output)}")
            print(f"[DC-SCM] [DEBUG] ERROR: CfmActiveIdentifier not found in CFM command output")
            print(f"[DC-SCM] [DEBUG] Expected pattern: 'CfmActiveIdentifier: <value>'")
            return None
            
        except Exception as e:
            logger.error(f"[DEBUG] Exception parsing CFM Active Identifier: {str(e)}")
            print(f"[DC-SCM] [DEBUG] Exception during parsing: {str(e)}")
            return None