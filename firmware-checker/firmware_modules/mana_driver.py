"""
MANA Driver Checker Module
Handles checking Microsoft Azure Network Adapter Virtual Bus driver version
"""

import logging
import subprocess
import winrm
import base64
import os
from datetime import datetime
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class ManaDriverChecker:
    """Checker for MANA (Microsoft Azure Network Adapter) driver version"""
    
    def __init__(self, os_username: Optional[str] = None, os_password: Optional[str] = None, timeout: int = 30):
        """
        Initialize MANA driver checker
        
        Args:
            os_username: Username for WinRM authentication
            os_password: Password for WinRM authentication  
            timeout: Timeout for operations in seconds
        """
        self.os_username = os_username
        self.os_password = os_password
        self.timeout = timeout
        
        # Default device name to check
        self.device_friendly_name = "Microsoft Azure Network Adapter Virtual Bus"
    
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
    
    def get_mana_driver_version(self, computer_name: str) -> Dict[str, Any]:
        """
        Get MANA driver version information
        
        Args:
            computer_name: The name or IP of the target computer
            
        Returns:
            Dictionary with driver version information
        """
        logger.info(f"Checking MANA driver version on {computer_name}")
        
        # Check if the target computer is reachable via ping
        if not self.test_ping_ipv4(computer_name):
            logger.warning(f"Ping to {computer_name} failed. Computer is not reachable.")
            return {
                'version': 'HOST_UNREACHABLE',
                'status': 'error',
                'error': 'Host unreachable via ping',
                'checked_at': datetime.now().isoformat(),
                'method': 'mana_driver_check'
            }
        
        try:
            # PowerShell script to get driver version using CIM
            ps_script = f"""
            $deviceName = "{self.device_friendly_name}"
            
            # Query using CIM for PnP devices
            $device = Get-CimInstance -ClassName Win32_PnPEntity | Where-Object {{ $_.Name -eq $deviceName }}
            
            if ($device) {{
                Write-Output "Device found: $($device.Name)"
                Write-Output "Status: $($device.Status)"
                Write-Output "Device ID: $($device.DeviceID)"
                Write-Output "Manufacturer: $($device.Manufacturer)"
                
                # Get driver information from Win32_PnPSignedDriver
                $driver = Get-CimInstance -ClassName Win32_PnPSignedDriver | Where-Object {{ $_.DeviceID -eq $device.DeviceID }}
                
                if ($driver) {{
                    Write-Output "Driver Version: $($driver.DriverVersion)"
                    Write-Output "Driver Date: $($driver.DriverDate)"
                    Write-Output "Driver Provider: $($driver.DriverProviderName)"
                    Write-Output "INF Name: $($driver.InfName)"
                    Write-Output "Signer: $($driver.Signer)"
                }} else {{
                    Write-Output "Driver information not available"
                }}
            }} else {{
                Write-Output "Error: Device '$deviceName' not found"
                Write-Output ""
                Write-Output "Available network/adapter devices:"
                Get-CimInstance -ClassName Win32_PnPEntity | Where-Object {{ 
                    $_.Name -like '*network*' -or 
                    $_.Name -like '*adapter*' -or
                    $_.Name -like '*ethernet*' -or
                    $_.Name -like '*azure*'
                }} | Select-Object -First 15 Name | ForEach-Object {{ Write-Output "  - $($_.Name)" }}
            }}
            """
            
            # Connect via WinRM or run locally
            if computer_name.lower() in ['localhost', '127.0.0.1', '.']:
                # For localhost, use subprocess with custom PowerShell path
                pwsh_exe = self.get_powershell_executable()
                result = subprocess.run(
                    [pwsh_exe, '-Command', ps_script],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout
                )
                output = result.stdout.strip()
                if result.stderr:
                    logger.warning(f"PowerShell stderr: {result.stderr}")
            else:
                # For remote machines, use WinRM
                if not self.os_username or not self.os_password:
                    return {
                        'version': 'NO_CREDENTIALS',
                        'status': 'error',
                        'error': 'Credentials required for remote connection',
                        'checked_at': datetime.now().isoformat(),
                        'method': 'mana_driver_check'
                    }
                
                # Create WinRM session
                session = winrm.Session(
                    f'http://{computer_name}:5985/wsman',
                    auth=(self.os_username, self.os_password),
                    transport='ntlm'
                )
                
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
                    return {
                        'version': 'EXECUTION_ERROR',
                        'status': 'error',
                        'error': f"Command execution failed: {error_msg}",
                        'checked_at': datetime.now().isoformat(),
                        'method': 'mana_driver_check'
                    }
                
                output = result.std_out.decode('utf-8').strip()
            
            # Parse the output to extract driver version
            return self._parse_driver_output(output)
            
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout while checking MANA driver on {computer_name}")
            return {
                'version': 'TIMEOUT_ERROR',
                'status': 'error',
                'error': f'Operation timed out after {self.timeout} seconds',
                'checked_at': datetime.now().isoformat(),
                'method': 'mana_driver_check'
            }
        except Exception as e:
            logger.error(f"Failed to check MANA driver on {computer_name}: {str(e)}")
            return {
                'version': 'EXCEPTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'mana_driver_check'
            }
    
    def _parse_driver_output(self, output: str) -> Dict[str, Any]:
        """Parse the PowerShell output to extract driver version information"""
        try:
            lines = output.split('\n')
            driver_info = {}
            
            # Parse output line by line
            for line in lines:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    driver_info[key.strip()] = value.strip()
            
            # Check for error conditions
            if "Error:" in output:
                return {
                    'version': 'DEVICE_NOT_FOUND',
                    'status': 'not_found',
                    'error': 'Microsoft Azure Network Adapter Virtual Bus device not found',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'mana_driver_check',
                    'raw_output': output
                }
            
            if "Driver information not available" in output:
                return {
                    'version': 'Driver information not available',
                    'status': 'not_found',
                    'error': 'Driver information could not be retrieved',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'mana_driver_check',
                    'device_info': driver_info
                }
            
            # Extract driver version
            driver_version = driver_info.get('Driver Version', 'UNKNOWN')
            
            if driver_version and driver_version != 'UNKNOWN':
                return {
                    'version': driver_version,
                    'status': 'success',
                    'error': None,
                    'checked_at': datetime.now().isoformat(),
                    'method': 'mana_driver_check',
                    'device_info': {
                        'device_name': driver_info.get('Device found', ''),
                        'device_status': driver_info.get('Status', ''),
                        'device_id': driver_info.get('Device ID', ''),
                        'manufacturer': driver_info.get('Manufacturer', ''),
                        'driver_version': driver_version,
                        'driver_date': driver_info.get('Driver Date', ''),
                        'driver_provider': driver_info.get('Driver Provider', ''),
                        'inf_name': driver_info.get('INF Name', ''),
                        'signer': driver_info.get('Signer', '')
                    }
                }
            else:
                return {
                    'version': 'Driver information not available',
                    'status': 'not_found',
                    'error': 'Driver version could not be extracted',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'mana_driver_check',
                    'raw_output': output
                }
                
        except Exception as e:
            logger.error(f"Error parsing driver output: {str(e)}")
            return {
                'version': 'PARSE_ERROR',
                'status': 'error',
                'error': f'Failed to parse driver output: {str(e)}',
                'checked_at': datetime.now().isoformat(),
                'method': 'mana_driver_check',
                'raw_output': output
            }