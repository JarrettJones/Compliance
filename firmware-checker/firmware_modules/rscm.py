"""
RSCM Firmware Checker Module
Handles checking firmware versions for RSCM (Rack Secure Control Module) using Redfish API
"""

import logging
import requests
import json
from datetime import datetime
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)

class RSCMChecker:
    """Checker for RSCM firmware using Redfish API"""
    
    def __init__(self, username='root', password='', timeout=30):
        """Initialize RSCM checker
        
        Args:
            username: RSCM username (default: root)
            password: RSCM password
            timeout: Request timeout in seconds
        """
        self.username = username
        self.password = password
        self.timeout = timeout
        
        # RSCM Redfish endpoint
        self.manager_endpoint = '/redfish/v1/Managers/RackManager'
        self.cpld_endpoint = '/redfish/v1/Chassis/RackManager/CPLD'
        self.cerberus_endpoint = '/redfish/v1/Chassis/RackManager/Cerberus'
        self.power_supplies_endpoint = '/redfish/v1/PowerEquipment/PowerShelves/1/PowerSupplies'
    
    def check_firmware(self, rscm_ip, rscm_port=8080):
        """Check RSCM firmware version using Redfish API
        
        Args:
            rscm_ip: RSCM IP address (e.g., 172.29.131.23)
            rscm_port: RSCM HTTPS port (default: 8080)
            
        Returns:
            dict: Results containing firmware version information
        """
        logger.info(f"Checking RSCM firmware for {rscm_ip}:{rscm_port}")
        print(f"[RSCM] Starting RSCM firmware check for {rscm_ip}:{rscm_port}")
        
        results = {
            'category': 'RSCM',
            'timestamp': datetime.now().isoformat(),
            'rscm_ip': rscm_ip,
            'rscm_port': rscm_port,
            'status': 'completed',
            'firmware_versions': {},
            'errors': []
        }
        
        try:
            # Test connection first
            print(f"[RSCM] Testing Redfish connection...")
            connection_test = self.test_connection(rscm_ip, rscm_port)
            if connection_test['status'] != 'success':
                print(f"[RSCM] Connection failed: {connection_test['message']}")
                results['status'] = 'error'
                results['errors'].append(connection_test['message'])
                return results
            
            print(f"[RSCM] Connection successful")
            
            # Get RSCM manager information
            print(f"[RSCM] Fetching RSCM manager information...")
            manager_data = self._get_redfish_data(rscm_ip, rscm_port, self.manager_endpoint)
            
            if not manager_data:
                error_msg = "Failed to retrieve RSCM manager data"
                print(f"[RSCM] {error_msg}")
                results['status'] = 'error'
                results['errors'].append(error_msg)
                return results
            
            print(f"[RSCM] Manager information retrieved successfully")
            
            # Extract firmware version information
            manager_type = manager_data.get('ManagerType', 'Unknown')
            model = manager_data.get('Model', 'Unknown')
            firmware_version = manager_data.get('FirmwareVersion', 'Unknown')
            
            results['firmware_versions'] = {
                'Manager Type': {
                    'version': manager_type,
                    'status': 'success' if manager_type != 'Unknown' else 'not_found'
                },
                'Model': {
                    'version': model,
                    'status': 'success' if model != 'Unknown' else 'not_found'
                },
                'Firmware Version': {
                    'version': firmware_version,
                    'status': 'success' if firmware_version != 'Unknown' else 'not_found'
                }
            }
            
            # Optional: Extract additional component versions if available
            oem_data = manager_data.get('Oem', {}).get('Microsoft', {})
            if 'Components' in oem_data:
                for component in oem_data['Components']:
                    comp_name = component.get('Name', 'Unknown')
                    comp_version = component.get('Version', 'Unknown')
                    results['firmware_versions'][f'Component: {comp_name}'] = {
                        'version': comp_version,
                        'status': 'success' if comp_version != 'Unknown' else 'not_found'
                    }
            
            # Optional: Extract FW update list if available
            if 'FWUpdateList' in oem_data:
                for fw_update in oem_data['FWUpdateList']:
                    fw_name = fw_update.get('Name', 'Unknown')
                    fw_version = fw_update.get('Version', 'Unknown')
                    results['firmware_versions'][f'FW Bank: {fw_name}'] = {
                        'version': fw_version,
                        'status': 'success' if fw_version != 'Unknown' else 'not_found'
                    }
            
            # Get CPLD version
            print(f"[RSCM] Fetching CPLD information...")
            cpld_data = self._get_redfish_data(rscm_ip, rscm_port, self.cpld_endpoint)
            
            if cpld_data:
                cpld_version = cpld_data.get('Version', 'Unknown')
                cpld_usercode = cpld_data.get('Usercode', 'Unknown')
                
                results['firmware_versions']['CPLD Version'] = {
                    'version': cpld_version,
                    'status': 'success' if cpld_version != 'Unknown' else 'not_found'
                }
                
                # Optionally include usercode as additional info
                if cpld_usercode != 'Unknown':
                    results['firmware_versions']['CPLD Usercode'] = {
                        'version': cpld_usercode,
                        'status': 'success'
                    }
                
                print(f"[RSCM] CPLD Version: {cpld_version}, Usercode: {cpld_usercode}")
            else:
                print(f"[RSCM] Warning: Could not retrieve CPLD data")
                results['firmware_versions']['CPLD Version'] = {
                    'version': 'NOT_AVAILABLE',
                    'status': 'not_found'
                }
            
            # Get Cerberus firmware version
            print(f"[RSCM] Fetching Cerberus information...")
            cerberus_data = self._get_redfish_data(rscm_ip, rscm_port, self.cerberus_endpoint)
            
            if cerberus_data:
                cerberus_fw_version = cerberus_data.get('FirmwareVersion', 'Unknown')
                pcd_data = cerberus_data.get('PCD', {})
                pcd_version_id = pcd_data.get('VersionID', 'Unknown')
                pcd_platform_id = pcd_data.get('PlatformID', 'Unknown')
                
                results['firmware_versions']['Cerberus FW Version'] = {
                    'version': cerberus_fw_version,
                    'status': 'success' if cerberus_fw_version != 'Unknown' else 'not_found'
                }
                
                results['firmware_versions']['Cerberus PCD Version'] = {
                    'version': pcd_version_id,
                    'status': 'success' if pcd_version_id != 'Unknown' else 'not_found'
                }
                
                # Optionally include PCD Platform ID
                if pcd_platform_id != 'Unknown':
                    results['firmware_versions']['Cerberus PCD Platform'] = {
                        'version': pcd_platform_id,
                        'status': 'success'
                    }
                
                print(f"[RSCM] Cerberus FW: {cerberus_fw_version}, PCD Version: {pcd_version_id}, Platform: {pcd_platform_id}")
            else:
                print(f"[RSCM] Warning: Could not retrieve Cerberus data")
                results['firmware_versions']['Cerberus FW Version'] = {
                    'version': 'NOT_AVAILABLE',
                    'status': 'not_found'
                }
            
            # Get Power Supply firmware versions
            print(f"[RSCM] Fetching Power Supply information...")
            ps_collection = self._get_redfish_data(rscm_ip, rscm_port, self.power_supplies_endpoint)
            
            if ps_collection and 'Members' in ps_collection:
                ps_members = ps_collection.get('Members', [])
                ps_count = len(ps_members)
                print(f"[RSCM] Found {ps_count} power supply(ies)")
                
                for ps_member in ps_members:
                    ps_uri = ps_member.get('@odata.id', '')
                    if not ps_uri:
                        continue
                    
                    # Extract power supply number from URI (e.g., "/redfish/v1/PowerEquipment/PowerShelves/1/PowerSupplies/1")
                    ps_number = ps_uri.split('/')[-1]
                    
                    # Get power supply details (Manufacturer, Model)
                    ps_data = self._get_redfish_data(rscm_ip, rscm_port, ps_uri)
                    
                    if ps_data:
                        manufacturer = ps_data.get('Manufacturer', 'Unknown')
                        model = ps_data.get('Model', 'Unknown')
                        
                        # Get power supply version information
                        ps_version_uri = f"{ps_uri}/Oem/Microsoft/Version"
                        ps_version_data = self._get_redfish_data(rscm_ip, rscm_port, ps_version_uri)
                        
                        if ps_version_data:
                            oem_ms = ps_version_data.get('Oem', {}).get('Microsoft', {})
                            active_image = oem_ms.get('ActiveImage', 'Unknown')
                            bootloader_version = oem_ms.get('BootloaderVersion', 'Unknown')
                            image_a_version = oem_ms.get('ImageAVersion', 'Unknown')
                            image_b_version = oem_ms.get('ImageBVersion', 'Unknown')
                            
                            # Add power supply info with manufacturer and model
                            ps_label = f"PSU {ps_number} ({manufacturer} {model})"
                            
                            results['firmware_versions'][f'{ps_label} - Active Image'] = {
                                'version': f"{active_image}",
                                'status': 'success' if active_image != 'Unknown' else 'not_found'
                            }
                            
                            results['firmware_versions'][f'{ps_label} - Bootloader'] = {
                                'version': bootloader_version,
                                'status': 'success' if bootloader_version != 'Unknown' else 'not_found'
                            }
                            
                            results['firmware_versions'][f'{ps_label} - Image A'] = {
                                'version': image_a_version,
                                'status': 'success' if image_a_version != 'Unknown' else 'not_found'
                            }
                            
                            results['firmware_versions'][f'{ps_label} - Image B'] = {
                                'version': image_b_version,
                                'status': 'success' if image_b_version != 'Unknown' else 'not_found'
                            }
                            
                            print(f"[RSCM] PSU {ps_number}: {manufacturer} {model}, Active: {active_image}, Bootloader: {bootloader_version}, ImageA: {image_a_version}, ImageB: {image_b_version}")
                        else:
                            print(f"[RSCM] Warning: Could not retrieve version data for PSU {ps_number}")
                    else:
                        print(f"[RSCM] Warning: Could not retrieve details for PSU {ps_number}")
            else:
                print(f"[RSCM] Warning: Could not retrieve power supply collection")
            
            print(f"[RSCM] Firmware check completed successfully")
            print(f"[RSCM] Manager Type: {manager_type}, Model: {model}, Firmware: {firmware_version}")
            
        except Exception as e:
            error_msg = f"Unexpected error during RSCM firmware check: {str(e)}"
            logger.error(error_msg, exc_info=True)
            print(f"[RSCM] {error_msg}")
            results['status'] = 'error'
            results['errors'].append(error_msg)
        
        return results
    
    def test_connection(self, rscm_ip, rscm_port=8080):
        """Test RSCM Redfish connection
        
        Args:
            rscm_ip: RSCM IP address
            rscm_port: RSCM HTTPS port
            
        Returns:
            dict: Connection test result
        """
        try:
            url = f"https://{rscm_ip}:{rscm_port}{self.manager_endpoint}"
            response = requests.get(
                url,
                auth=HTTPBasicAuth(self.username, self.password),
                verify=False,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return {
                    'status': 'success',
                    'message': 'Successfully connected to RSCM Redfish API'
                }
            else:
                return {
                    'status': 'error',
                    'message': f'HTTP {response.status_code}: {response.reason}'
                }
                
        except requests.exceptions.Timeout:
            return {
                'status': 'error',
                'message': f'Connection timeout after {self.timeout} seconds'
            }
        except requests.exceptions.ConnectionError as e:
            return {
                'status': 'error',
                'message': f'Connection error: {str(e)}'
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Unexpected error: {str(e)}'
            }
    
    def _get_redfish_data(self, rscm_ip, rscm_port, endpoint):
        """Get data from RSCM Redfish API endpoint
        
        Args:
            rscm_ip: RSCM IP address
            rscm_port: RSCM HTTPS port
            endpoint: Redfish API endpoint path
            
        Returns:
            dict: JSON response data or None on error
        """
        try:
            url = f"https://{rscm_ip}:{rscm_port}{endpoint}"
            logger.debug(f"Fetching RSCM data from: {url}")
            
            response = requests.get(
                url,
                auth=HTTPBasicAuth(self.username, self.password),
                verify=False,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Failed to fetch {endpoint}: HTTP {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error fetching RSCM data from {endpoint}: {str(e)}")
            return None
