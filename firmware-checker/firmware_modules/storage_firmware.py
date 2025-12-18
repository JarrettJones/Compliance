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
            
            # Get disk details from PowerShell (model, serial, size) - THIS IS THE PRIMARY SOURCE
            logger.info(f"Collecting disk details via PowerShell for {computer_name}")
            disk_details = self._get_disk_details_powershell(computer_name)
            
            if not disk_details:
                return {
                    'status': 'error',
                    'error': 'Failed to collect disk information via PowerShell',
                    'raw_output': '',
                    'storage_devices': {}
                }
            
            # Build storage devices from PowerShell Get-Disk data (primary source)
            storage_devices = {}
            for disk_num, ps_details in disk_details.items():
                device_key = f"Disk_{disk_num}"
                model = ps_details.get('model', '')
                size_gb = ps_details.get('size_gb', 0)
                location = ps_details.get('location_path', '')
                
                # Classify device as M.2 or E.1s based on size and location
                device_type = self._classify_device_by_characteristics(model, size_gb, location)
                
                storage_devices[device_key] = {
                    'disk_number': disk_num,
                    'model': model,
                    'serial_number': ps_details.get('serial_number', ''),
                    'firmware_version': ps_details.get('firmware_version', ''),
                    'bus_type': ps_details.get('bus_type', ''),
                    'size_gb': size_gb,
                    'device_type': device_type,
                    'friendly_name': ps_details.get('friendly_name', ''),
                    'location_path': location,
                    'partition_style': ps_details.get('partition_style', '')
                }
                
                logger.debug(f"Disk {disk_num}: {model} - {size_gb}GB - Classified as {device_type}")
            
            logger.info(f"Successfully collected data for {len(storage_devices)} disk(s) from PowerShell")
            
            return {
                'status': 'success',
                'error': None,
                'storage_devices': storage_devices
            }
            
        except Exception as e:
            error_str = str(e).lower()
            logger.error(f"Error checking storage firmware on {computer_name}: {str(e)}")
            
            # Check if it's a connection/network error
            if any(keyword in error_str for keyword in ['connection', 'network', 'unreachable', 'timeout', 'wsman', 'winrm', 'refused']):
                return {
                    'status': 'error',
                    'error': f'Cannot connect to {computer_name}: {str(e)}',
                    'version': 'UNREACHABLE - Check Network',
                    'raw_output': '',
                    'storage_devices': {}
                }
            
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
    
    def _get_disk_details_powershell(self, computer_name: str) -> Dict[str, Dict[str, Any]]:
        """Get disk details using PowerShell Get-Disk command"""
        disk_details = {}
        
        try:
            # PowerShell script to get disk information
            # Note: Using if-else to handle null Size values
            ps_script = """
            Get-Disk | Where-Object { $_.BusType -in @('NVMe','SATA') } | ForEach-Object {
                $sizeGB = if ($_.Size -and $_.Size -gt 0) { [math]::Round($_.Size/1GB,2) } else { 0 }
                [PSCustomObject]@{
                    Number = $_.Number
                    FriendlyName = if ($_.FriendlyName) { $_.FriendlyName } else { '' }
                    Model = if ($_.Model) { $_.Model } else { '' }
                    SerialNumber = if ($_.SerialNumber) { $_.SerialNumber } else { '' }
                    FirmwareVersion = if ($_.FirmwareVersion) { $_.FirmwareVersion } else { '' }
                    BusType = if ($_.BusType) { $_.BusType } else { '' }
                    SizeGB = $sizeGB
                    PartitionStyle = if ($_.PartitionStyle) { $_.PartitionStyle } else { '' }
                    LocationPath = if ($_.LocationPath) { $_.LocationPath } else { '' }
                }
            } | ConvertTo-Json -Compress
            """
            
            is_remote = computer_name.lower() not in ['localhost', '127.0.0.1', '.']
            
            if is_remote:
                if not WINRM_AVAILABLE or not self.os_username or not self.os_password:
                    logger.warning(f"WinRM not available or missing credentials for {computer_name}")
                    return {}
                
                logger.info(f"Executing Get-Disk via WinRM on {computer_name}")
                session = winrm.Session(
                    f'http://{computer_name}:5985/wsman',
                    auth=(self.os_username, self.os_password),
                    transport='ntlm'
                )
                
                # Use encoded command approach to avoid PATH issues
                # Try multiple PowerShell paths like we do for UpdateStorageFirmware
                pwsh_paths = [
                    r'D:\Tools\PowerShell\pwsh.exe',
                    r'C:\Program Files\PowerShell\7\pwsh.exe',
                    r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
                ]
                
                encoded_script = base64.b64encode(ps_script.encode('utf-16-le')).decode('ascii')
                
                result = None
                for pwsh_path in pwsh_paths:
                    try:
                        cmd = f'{pwsh_path} -NoProfile -EncodedCommand {encoded_script}'
                        result = session.run_cmd(cmd)
                        
                        if result.status_code == 0:
                            logger.info(f"Get-Disk succeeded using {pwsh_path}")
                            break
                        else:
                            logger.debug(f"PowerShell path {pwsh_path} failed with status {result.status_code}")
                    except Exception as e:
                        logger.debug(f"PowerShell path {pwsh_path} exception: {e}")
                        continue
                
                if not result or result.status_code != 0:
                    logger.error(f"All PowerShell paths failed for Get-Disk command")
                    return {}
                
                output = result.std_out.decode('utf-8').strip()
                stderr = result.std_err.decode('utf-8').strip()
                
                if stderr:
                    logger.warning(f"Get-Disk stderr: {stderr}")
                    
                logger.info(f"Get-Disk WinRM output length: {len(output)} chars")
            else:
                logger.info(f"Executing Get-Disk locally")
                pwsh_exe = self.get_powershell_executable()
                result = subprocess.run(
                    [pwsh_exe, '-Command', ps_script],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout
                )
                output = result.stdout.strip()
                
                if result.returncode != 0:
                    logger.error(f"Get-Disk command failed: {result.stderr}")
                    return {}
                
                logger.info(f"Get-Disk local output length: {len(output)} chars")
            
            # Parse JSON output
            if output:
                import json
                logger.debug(f"PowerShell Get-Disk output: {output[:500]}")  # Log first 500 chars
                try:
                    disks_data = json.loads(output)
                    
                    # Handle single disk vs multiple disks
                    if isinstance(disks_data, dict):
                        disks_data = [disks_data]
                    
                    logger.info(f"Parsed {len(disks_data)} disk(s) from Get-Disk output")
                    
                    for disk in disks_data:
                        disk_num = str(disk.get('Number', ''))
                        size_gb = disk.get('SizeGB', 0)
                        logger.debug(f"Disk {disk_num}: Model={disk.get('Model', 'N/A')}, Size={size_gb}GB, Serial={disk.get('SerialNumber', 'N/A')}")
                        disk_details[disk_num] = {
                            'friendly_name': disk.get('FriendlyName', ''),
                            'model': disk.get('Model', ''),
                            'serial_number': disk.get('SerialNumber', ''),
                            'firmware_version': disk.get('FirmwareVersion', ''),
                            'bus_type': disk.get('BusType', ''),
                            'size_gb': size_gb,
                            'partition_style': disk.get('PartitionStyle', ''),
                            'location_path': disk.get('LocationPath', '')
                        }
                except json.JSONDecodeError as je:
                    logger.error(f"Failed to parse JSON from Get-Disk: {je}")
            else:
                logger.warning("Get-Disk PowerShell command returned empty output")
        
        except Exception as e:
            logger.warning(f"Could not get disk details via PowerShell: {e}")
        
        return disk_details
    
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
    
    def _classify_device_by_characteristics(self, model: str, size_gb: float, location: str) -> str:
        """
        Classify storage device as M.2 or E.1s based on model, size, and physical location
        
        M.2 drives are typically:
        - Smaller capacity (< 2TB usually)
        - Consumer brands (Samsung, WD, Intel, etc.)
        - Often in PCI Slot 10 (boot drive location)
        
        E.1s drives are typically:
        - Larger capacity (3TB+ for data storage)
        - Enterprise/OEM drives
        - Multiple identical drives in sequential slots
        """
        model_upper = model.upper()
        
        # M.2 consumer brand indicators
        m2_brands = [
            'MZVL',      # Samsung PM9A1, 983 series
            'SAMSUNG',   # Samsung consumer
            'WD', 'WDS', # Western Digital
            'INTEL',     # Intel
            'KINGSTON',  # Kingston
            'CRUCIAL',   # Crucial
            'CORSAIR',   # Corsair
            'ADATA',     # ADATA
            'SABRENT'    # Sabrent
        ]
        
        # Check for M.2 brand patterns
        for brand in m2_brands:
            if brand in model_upper:
                # M.2 drives are typically smaller (boot drives)
                if size_gb > 0 and size_gb < 2000:  # Less than 2TB
                    return 'M.2'
        
        # E.1s enterprise drive indicators  
        e1s_patterns = [
            'HFS',       # SK Hynix Enterprise (HFS3T8GFMWX183N)
            'OSNN',      # Enterprise OEM
            'E1S', 'E.1S',
            'ENTERPRISE',
            'DATACENTER'
        ]
        
        # Check for explicit E.1s patterns
        for pattern in e1s_patterns:
            if pattern in model_upper:
                return 'E.1s'
        
        # Size-based heuristic: Large drives (>= 2TB) are likely E.1s data drives
        if size_gb >= 2000:
            return 'E.1s'
        
        # Location-based heuristic: Slot 10 is typically boot drive (M.2)
        if 'SLOT 10' in location.upper():
            return 'M.2'
        
        # Default: if it's NVMe and not clearly M.2, assume E.1s
        return 'E.1s'
    
    def get_m2_devices(self, computer_name: str) -> Dict[str, Any]:
        """Get M.2 device information - returns combined drive info with expandable details"""
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
        
        # Create summary version string
        if len(sorted_devices) == 1:
            device_info = sorted_devices[0][1]
            model = device_info.get('model', device_info.get('vendor_product', 'Unknown'))
            firmware_ver = device_info['firmware_version']
            size_gb = device_info.get('size_gb', 0)
            version = f"{size_gb}GB {model} FW:{firmware_ver}"
        else:
            version = f"{len(sorted_devices)} M.2 drives detected"
        
        # Prepare detailed device list
        device_details = []
        for device_id, device_info in sorted_devices:
            device_details.append({
                'disk_number': device_info['disk_number'],
                'model': device_info.get('model', device_info.get('vendor_product', 'Unknown')),
                'serial_number': device_info.get('serial_number', 'N/A'),
                'firmware_version': device_info['firmware_version'],
                'size_gb': device_info.get('size_gb', 0),
                'bus_type': device_info.get('bus_type', 'Unknown')
            })
        
        return {
            'version': version,
            'status': 'success',
            'error': None,
            'checked_at': datetime.now().isoformat(),
            'method': 'storage_firmware_tool',
            'storage_drives': device_details,
            'drive_count': len(sorted_devices)
        }
    
    def get_e1s_devices(self, computer_name: str) -> Dict[str, Any]:
        """Get E.1s device information - returns combined drive info with expandable details"""
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
        
        # Create summary version string
        if len(sorted_devices) == 1:
            device_info = sorted_devices[0][1]
            model = device_info.get('model', device_info.get('vendor_product', 'Unknown'))
            firmware_ver = device_info['firmware_version']
            size_gb = device_info.get('size_gb', 0)
            version = f"{size_gb}GB {model} FW:{firmware_ver}"
        else:
            version = f"{len(sorted_devices)} E.1s drives detected"
        
        # Prepare detailed device list
        device_details = []
        for device_id, device_info in sorted_devices:
            device_details.append({
                'disk_number': device_info['disk_number'],
                'model': device_info.get('model', device_info.get('vendor_product', 'Unknown')),
                'serial_number': device_info.get('serial_number', 'N/A'),
                'firmware_version': device_info['firmware_version'],
                'size_gb': device_info.get('size_gb', 0),
                'bus_type': device_info.get('bus_type', 'Unknown')
            })
        
        return {
            'version': version,
            'status': 'success',
            'error': None,
            'checked_at': datetime.now().isoformat(),
            'method': 'storage_firmware_tool',
            'storage_drives': device_details,
            'drive_count': len(sorted_devices)
        }