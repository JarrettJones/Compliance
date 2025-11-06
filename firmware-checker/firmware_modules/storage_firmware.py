"""
Storage Firmware Checker Module
Handles checking M.2 and E.1s firmware versions using UpdateStorageFirmware.exe
"""

import subprocess
import re
import os
import logging
import base64
from datetime import datetime
from typing import Optional, Dict, Any
try:
    import winrm
    WINRM_AVAILABLE = True
except ImportError:
    WINRM_AVAILABLE = False
    winrm = None

logger = logging.getLogger(__name__)

class StorageFirmwareChecker:
    """Checker for M.2 and E.1s storage firmware using UpdateStorageFirmware.exe"""
    
    def __init__(self, os_username: Optional[str] = None, os_password: Optional[str] = None, timeout: int = 60):
        """
        Initialize StorageFirmwareChecker
        
        Args:
            os_username: Windows OS username for remote access
            os_password: Windows OS password for remote access
            timeout: Timeout for operations in seconds
        """
        self.os_username = os_username
        self.os_password = os_password
        self.timeout = timeout
        # Try .exe first, then .bat for testing
        base_path = os.path.dirname(os.path.dirname(__file__))
        exe_path = os.path.join(base_path, "UpdateStorageFirmware.exe")
        bat_path = os.path.join(base_path, "UpdateStorageFirmware.bat")
        
        if os.path.exists(exe_path):
            self.local_exe_path = exe_path
        elif os.path.exists(bat_path):
            self.local_exe_path = bat_path
        else:
            self.local_exe_path = exe_path  # Default to .exe path for error reporting
    
    def get_powershell_executable(self) -> str:
        """Get the PowerShell executable path, preferring custom installation."""
        custom_pwsh = r"D:\Tools\PowerShell\pwsh.exe"
        if os.path.exists(custom_pwsh):
            return custom_pwsh
        return "powershell.exe"
    
    def test_ping_ipv4(self, computer_name: str) -> bool:
        """Check if the target computer is reachable via ping."""
        try:
            result = subprocess.run(
                ['ping', '-n', '1', '-w', '1000', computer_name],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def check_storage_firmware(self, computer_name: str) -> Dict[str, Any]:
        """
        Check storage firmware versions on the specified computer
        
        Args:
            computer_name: The name or IP of the target computer
            
        Returns:
            Dictionary with parsed storage firmware information
        """
        try:
            # Check if the target computer is reachable via ping
            if not self.test_ping_ipv4(computer_name):
                logger.warning(f"Ping to {computer_name} failed. Computer is not reachable.")
                return {
                    'status': 'error',
                    'error': 'Host unreachable',
                    'raw_output': '',
                    'storage_devices': {}
                }
            
            # Check if local exe exists
            if not os.path.exists(self.local_exe_path):
                error_msg = f"Local UpdateStorageFirmware.exe not found at {self.local_exe_path}"
                logger.error(error_msg)
                return {
                    'status': 'error',
                    'error': error_msg,
                    'raw_output': '',
                    'storage_devices': {}
                }
            
            # Execute the storage firmware check
            raw_output = self._execute_storage_command(computer_name)
            
            if raw_output.startswith("Error:"):
                return {
                    'status': 'error',
                    'error': raw_output,
                    'raw_output': raw_output,
                    'storage_devices': {}
                }
            
            # Parse the output to extract storage device information
            storage_devices = self._parse_storage_output(raw_output)
            
            return {
                'status': 'success',
                'error': None,
                'raw_output': raw_output,
                'storage_devices': storage_devices
            }
            
        except Exception as e:
            logger.error(f"Error checking storage firmware on {computer_name}: {str(e)}")
            return {
                'status': 'error',
                'error': str(e),
                'raw_output': '',
                'storage_devices': {}
            }
    
    def _execute_storage_command(self, computer_name: str) -> str:
        """Execute the UpdateStorageFirmware.exe command on the target computer"""
        is_remote = computer_name.lower() not in ['localhost', '127.0.0.1', '.']
        
        if is_remote and not WINRM_AVAILABLE:
            return "Error: pywinrm not installed. Required for remote connections."
        
        if is_remote:
            return self._execute_remote_command(computer_name)
        else:
            return self._execute_local_command()
    
    def _execute_local_command(self) -> str:
        """Execute UpdateStorageFirmware.exe locally"""
        try:
            # PowerShell script to run command locally
            ps_script = f"""
            $exePath = "{self.local_exe_path}"
            if (Test-Path -Path $exePath) {{
                Write-Output "UpdateStorageFirmware found. Running command..."
                $output = & "$exePath" -list disk 2>&1 | Out-String
                Write-Output $output
            }}
            else {{
                Write-Output "Error: UpdateStorageFirmware not found at $exePath"
            }}
            """
            
            # Use custom PowerShell path if available
            pwsh_exe = self.get_powershell_executable()
            result = subprocess.run(
                [pwsh_exe, '-Command', ps_script],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.stderr:
                logger.warning(f"PowerShell stderr: {result.stderr}")
            
            return result.stdout.strip()
            
        except Exception as e:
            return f"Error: {str(e)}"
    
    def _execute_remote_command(self, computer_name: str) -> str:
        """Execute UpdateStorageFirmware.exe on remote computer"""
        if not self.os_username or not self.os_password:
            return "Error: OS credentials required for remote connection"
        
        try:
            # Create WinRM session
            session = winrm.Session(
                f'http://{computer_name}:5985/wsman',
                auth=(self.os_username, self.os_password),
                transport='ntlm'
            )
            
            # Check if file exists on remote D:\\
            check_script = 'Test-Path -Path "D:\\UpdateStorageFirmware.exe"'
            result = session.run_ps(check_script)
            file_exists = result.std_out.decode('utf-8').strip().lower() == 'true'
            
            if not file_exists:
                logger.info(f"UpdateStorageFirmware.exe not found on {computer_name}. Copying file...")
                
                # Copy file to remote computer
                copy_result = self._copy_file_to_remote(computer_name)
                if not copy_result:
                    return "Error: Failed to copy UpdateStorageFirmware.exe to remote computer"
            
            # PowerShell script to run command on remote machine
            ps_script = """
            Set-Location D:\\
            if (Test-Path -Path "D:\\UpdateStorageFirmware.exe") {
                Write-Output "UpdateStorageFirmware.exe found. Running command..."
                $output = & .\\UpdateStorageFirmware.exe -list disk 2>&1 | Out-String
                Write-Output $output
            }
            else {
                Write-Output "Error: UpdateStorageFirmware.exe not found on D:\\"
                Write-Output "Checking D:\\ contents:"
                Get-ChildItem -Path "D:\\" -File | ForEach-Object { Write-Output "  $($_.Name)" }
            }
            """
            
            # Try multiple PowerShell paths - check custom path first, then fallback to system paths
            pwsh_paths = [
                r'D:\Tools\PowerShell\pwsh.exe',
                r'C:\Program Files\PowerShell\7\pwsh.exe',
                r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
            ]
            
            # Encode the PowerShell script to avoid quoting issues
            encoded_script = base64.b64encode(ps_script.encode('utf-16-le')).decode('ascii')
            
            result = None
            last_error = None
            
            for pwsh_path in pwsh_paths:
                try:
                    # Use -EncodedCommand to pass the script safely
                    cmd = f'{pwsh_path} -NoProfile -EncodedCommand {encoded_script}'
                    result = session.run_cmd(cmd)
                    
                    if result.status_code == 0:
                        break  # Success, use this result
                    else:
                        last_error = result.std_err.decode('utf-8')
                        logger.debug(f"PowerShell path {pwsh_path} failed: {last_error}")
                except Exception as e:
                    last_error = str(e)
                    logger.debug(f"PowerShell path {pwsh_path} exception: {last_error}")
                    continue
            
            if not result or result.status_code != 0:
                error_msg = last_error or "All PowerShell paths failed"
                logger.error(f"Command execution error: {error_msg}")
                return f"Error: {error_msg}"
            
            output = result.std_out.decode('utf-8').strip()
            return output
            
        except Exception as e:
            logger.error(f"Failed to execute remote command: {str(e)}")
            return f"Error: {str(e)}"
    
    def _copy_file_to_remote(self, computer_name: str) -> bool:
        """Copy UpdateStorageFirmware.exe to remote computer"""
        try:
            remote_path = f"\\\\{computer_name}\\D$\\UpdateStorageFirmware.exe"
            
            # Map the network drive with credentials
            net_use_cmd = f'net use \\\\{computer_name}\\D$ /user:{self.os_username} {self.os_password}'
            
            result = subprocess.run(
                ['cmd', '/c', net_use_cmd],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                logger.error(f"Failed to map network drive: {result.stderr}")
                return False
            
            # Copy the file
            import shutil
            try:
                shutil.copy2(self.local_exe_path, remote_path)
                logger.info(f"File copied to {remote_path}")
                return True
            except Exception as copy_error:
                logger.error(f"Error copying file: {copy_error}")
                return False
            finally:
                # Clean up the network connection
                subprocess.run(
                    ['cmd', '/c', f'net use \\\\{computer_name}\\D$ /delete'], 
                    capture_output=True, 
                    timeout=10
                )
        
        except Exception as e:
            logger.error(f"Error in file copy operation: {str(e)}")
            return False
    
    def _parse_storage_output(self, output: str) -> Dict[str, Dict[str, Any]]:
        """Parse the output from UpdateStorageFirmware.exe to extract device information"""
        devices = {}
        
        try:
            lines = output.split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Remove timestamp prefix if present: [2025-10-31-23:34:14:913, 14744, 16368] 
                if line.startswith('[') and '] ' in line:
                    line = line.split('] ', 1)[1]
                
                # Look for disk entries in the table format
                # Format: Disk X   | NVME    | SSD  | address | VendorId ProductId | SerialNumber | ActiveFW | PendingFW
                if line.startswith('Disk ') and '|' in line:
                    parts = [part.strip() for part in line.split('|')]
                    
                    if len(parts) >= 7:  # Ensure we have all expected columns
                        disk_info = parts[0].strip()  # "Disk X"
                        bus_type = parts[1].strip()   # "NVME", "SATA", etc.
                        device_type = parts[2].strip()  # "SSD", "HDD", etc.
                        scsi_address = parts[3].strip()
                        vendor_product = parts[4].strip()
                        serial_number = parts[5].strip()
                        active_fw = parts[6].strip()
                        pending_fw = parts[7].strip() if len(parts) > 7 else 'NA'
                        
                        # Extract disk number
                        disk_match = re.match(r'Disk (\d+)', disk_info)
                        if disk_match:
                            disk_num = disk_match.group(1)
                            device_key = f"Disk_{disk_num}"
                            
                            # Determine if this is M.2 or E.1s based on vendor/product ID pattern
                            # M.2 devices typically have different vendor patterns
                            # Based on your example: OSNN devices seem to be E.1s, MZVL* seems to be M.2
                            device_classification = self._classify_storage_device(vendor_product, bus_type)
                            
                            devices[device_key] = {
                                'disk_number': disk_num,
                                'bus_type': bus_type,
                                'device_type_hw': device_type,  # SSD/HDD
                                'scsi_address': scsi_address,
                                'vendor_product': vendor_product,
                                'serial_number': serial_number,
                                'firmware_version': active_fw,
                                'pending_firmware': pending_fw,
                                'device_type': device_classification,  # M.2 or E.1s
                                'status': 'detected'
                            }
        
        except Exception as e:
            logger.error(f"Error parsing storage output: {str(e)}")
        
        return devices
    
    def _classify_storage_device(self, vendor_product: str, bus_type: str) -> str:
        """Classify storage device as M.2, E.1s, or Other based on vendor/product patterns"""
        vendor_product_upper = vendor_product.upper()
        
        # M.2 device patterns - Samsung is the most reliable indicator
        # Samsung M.2 SSDs typically start with MZ* model numbers
        samsung_m2_patterns = [
            'MZVL',  # Samsung PM9A1, PM981a, etc. (like MZVL6960HFLB-00AMV from your example)
            'MZ-VL', 
            'MZVK',  # Samsung PM9B1
            'MZQL',  # Samsung PM1735
            'MZ7L',  # Samsung PM893
            'MZ-7L',
            'MZ9L',  # Samsung PM9C1
            'SAMSUNG'
        ]
        
        # Other M.2 device patterns
        other_m2_patterns = [
            'WDS',   # Western Digital M.2
            'WD_BLACK', 'WD BLACK',
            'INTEL SSD',
            'SSDPE',  # Intel NVMe
            'SSDPF',  # Intel Optane
            'THNSN',  # Toshiba/Kioxia M.2
            'KXG',    # Toshiba/Kioxia
            '980 PRO', '970 EVO', '960 EVO',  # Samsung consumer model names
            'CRUCIAL', 'CT',  # Crucial M.2
            'CORSAIR',
            'KINGSTON'
        ]
        
        # Check for Samsung M.2 first (most reliable for your use case)
        for pattern in samsung_m2_patterns:
            if pattern in vendor_product_upper:
                return 'M.2'
        
        # Check for other M.2 patterns
        for pattern in other_m2_patterns:
            if pattern in vendor_product_upper:
                return 'M.2'
        
        # E.1s device patterns - more flexible since they vary
        # If it's NVMe but not identified as M.2, and meets certain criteria, it's likely E.1s
        e1s_indicators = [
            'OSNN',  # Based on your example
            'E1S', 'E.1S',  # Explicit E.1s naming
            'ENTERPRISE',
            'DC ',   # Data center drives
            'DATACENTER'
        ]
        
        # Check for explicit E.1s patterns
        for pattern in e1s_indicators:
            if pattern in vendor_product_upper:
                return 'E.1s'
        
        # Heuristic: If it's NVMe and not identified as M.2, 
        # and the vendor/product string is short (like "OSNN"), it might be E.1s
        if (bus_type.upper() == 'NVME' and 
            len(vendor_product.strip()) <= 8 and  # Short vendor strings often indicate OEM/enterprise drives
            not any(consumer in vendor_product_upper for consumer in ['SAMSUNG', 'WD', 'INTEL', 'CRUCIAL', 'CORSAIR'])):
            return 'E.1s'
        
        # If NVMe but no clear classification, default to E.1s (more common in these enterprise systems)
        if bus_type.upper() == 'NVME':
            return 'E.1s'
        
        # Default fallback
        return 'Other'
    
    def get_m2_devices(self, computer_name: str) -> Dict[str, Any]:
        """Get M.2 device information - returns combined drive info"""
        storage_info = self.check_storage_firmware(computer_name)
        
        if storage_info['status'] != 'success':
            return {
                'version': 'CONNECTION_FAILED',
                'status': 'error',
                'error': storage_info['error'],
                'checked_at': datetime.now().isoformat(),
                'method': 'storage_firmware_tool'
            }
        
        # Filter M.2 devices and sort by disk number
        m2_devices = {k: v for k, v in storage_info['storage_devices'].items() 
                      if v.get('device_type') == 'M.2'}
        
        if not m2_devices:
            return {
                'version': 'NO_M2_DEVICE_FOUND',
                'status': 'not_found',
                'error': 'No M.2 device detected',
                'checked_at': datetime.now().isoformat(),
                'method': 'storage_firmware_tool'
            }
        
        # Sort devices by disk number
        sorted_devices = sorted(m2_devices.items(), key=lambda x: int(x[1]['disk_number']))
        
        # Create combined version string with drive numbers and versions
        version_parts = []
        device_details = []
        
        for device_id, device_info in sorted_devices:
            disk_num = device_info['disk_number']
            firmware_ver = device_info['firmware_version']
            version_parts.append(f"Drive {disk_num}: {firmware_ver}")
            device_details.append(device_info)
        
        combined_version = " | ".join(version_parts)
        
        return {
            'version': combined_version,
            'status': 'success',
            'error': None,
            'checked_at': datetime.now().isoformat(),
            'method': 'storage_firmware_tool',
            'device_info': {
                'device_count': len(sorted_devices),
                'devices': device_details
            }
        }
    
    def get_e1s_devices(self, computer_name: str) -> Dict[str, Any]:
        """Get E.1s device information - returns combined drive info"""
        storage_info = self.check_storage_firmware(computer_name)
        
        if storage_info['status'] != 'success':
            return {
                'version': 'CONNECTION_FAILED',
                'status': 'error',
                'error': storage_info['error'],
                'checked_at': datetime.now().isoformat(),
                'method': 'storage_firmware_tool'
            }
        
        # Filter E.1s devices and sort by disk number
        e1s_devices = {k: v for k, v in storage_info['storage_devices'].items() 
                       if v.get('device_type') == 'E.1s'}
        
        if not e1s_devices:
            return {
                'version': 'NO_E1S_DEVICE_FOUND',
                'status': 'not_found',
                'error': 'No E.1s device detected',
                'checked_at': datetime.now().isoformat(),
                'method': 'storage_firmware_tool'
            }
        
        # Sort devices by disk number
        sorted_devices = sorted(e1s_devices.items(), key=lambda x: int(x[1]['disk_number']))
        
        # Create combined version string with drive numbers and versions
        version_parts = []
        device_details = []
        
        for device_id, device_info in sorted_devices:
            disk_num = device_info['disk_number']
            firmware_ver = device_info['firmware_version']
            version_parts.append(f"Drive {disk_num}: {firmware_ver}")
            device_details.append(device_info)
        
        combined_version = " | ".join(version_parts)
        
        return {
            'version': combined_version,
            'status': 'success',
            'error': None,
            'checked_at': datetime.now().isoformat(),
            'method': 'storage_firmware_tool',
            'device_info': {
                'device_count': len(sorted_devices),
                'devices': device_details
            }
        }