"""
DIMM Information Checker Module
Handles checking DIMM/memory information using PowerShell WMI queries
"""

import subprocess
import logging
import base64
from datetime import datetime
from typing import Optional, Dict, Any, List
try:
    import winrm
    WINRM_AVAILABLE = True
except ImportError:
    WINRM_AVAILABLE = False
    winrm = None

logger = logging.getLogger(__name__)

class DIMMInfoChecker:
    """Checker for DIMM/Memory information using Win32_PhysicalMemory"""
    
    def __init__(self, os_username: Optional[str] = None, os_password: Optional[str] = None, timeout: int = 30):
        """
        Initialize DIMMInfoChecker
        
        Args:
            os_username: Windows OS username for remote access
            os_password: Windows OS password for remote access
            timeout: Timeout for operations in seconds
        """
        self.os_username = os_username
        self.os_password = os_password
        self.timeout = timeout
    
    def get_powershell_executable(self) -> str:
        """Get the PowerShell executable path, preferring custom installation."""
        import os
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
    
    def get_dimm_info(self, computer_name: str) -> Dict[str, Any]:
        """
        Get DIMM/Memory information from the specified computer
        
        Args:
            computer_name: The name or IP of the target computer
            
        Returns:
            Dictionary with DIMM information
        """
        logger.info(f"Checking DIMM information on {computer_name}")
        
        # Check if the target computer is reachable via ping
        if not self.test_ping_ipv4(computer_name):
            logger.warning(f"Ping to {computer_name} failed. Computer is not reachable.")
            return {
                'status': 'error',
                'error': 'Host unreachable via ping',
                'dimm_count': 0,
                'total_capacity_gb': 0,
                'dimms': [],
                'checked_at': datetime.now().isoformat(),
                'method': 'dimm_info_check'
            }
        
        try:
            # PowerShell script to get DIMM information
            ps_script = """
            $dimms = Get-CimInstance -ClassName Win32_PhysicalMemory | Select-Object BankLabel, Capacity, Manufacturer, PartNumber, Speed, SerialNumber
            
            if ($dimms) {
                $dimmList = @()
                foreach ($dimm in $dimms) {
                    $dimmList += @{
                        BankLabel = $dimm.BankLabel
                        Capacity = $dimm.Capacity
                        Manufacturer = $dimm.Manufacturer
                        PartNumber = $dimm.PartNumber
                        Speed = $dimm.Speed
                        SerialNumber = $dimm.SerialNumber
                    }
                }
                $dimmList | ConvertTo-Json -Depth 3
            }
            else {
                Write-Output "Error: No DIMM information found"
            }
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
                        'status': 'error',
                        'error': 'Credentials required for remote connection',
                        'dimm_count': 0,
                        'total_capacity_gb': 0,
                        'dimms': [],
                        'checked_at': datetime.now().isoformat(),
                        'method': 'dimm_info_check'
                    }
                
                if not WINRM_AVAILABLE:
                    return {
                        'status': 'error',
                        'error': 'pywinrm not installed. Required for remote connections.',
                        'dimm_count': 0,
                        'total_capacity_gb': 0,
                        'dimms': [],
                        'checked_at': datetime.now().isoformat(),
                        'method': 'dimm_info_check'
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
                        'status': 'error',
                        'error': f"Command execution failed: {error_msg}",
                        'dimm_count': 0,
                        'total_capacity_gb': 0,
                        'dimms': [],
                        'checked_at': datetime.now().isoformat(),
                        'method': 'dimm_info_check'
                    }
                
                output = result.std_out.decode('utf-8').strip()
            
            # Parse the output to extract DIMM information
            return self._parse_dimm_output(output)
            
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout while checking DIMM information on {computer_name}")
            return {
                'status': 'error',
                'error': 'Timeout while checking DIMM information',
                'dimm_count': 0,
                'total_capacity_gb': 0,
                'dimms': [],
                'checked_at': datetime.now().isoformat(),
                'method': 'dimm_info_check'
            }
        except Exception as e:
            logger.error(f"Error checking DIMM information on {computer_name}: {str(e)}")
            
            # Check if it's a connection/network error
            error_str = str(e).lower()
            if any(keyword in error_str for keyword in ['connection', 'network', 'unreachable', 'timeout', 'wsman', 'winrm', 'refused']):
                return {
                    'status': 'error',
                    'error': f'Cannot connect to {computer_name}: {str(e)}',
                    'dimm_count': 0,
                    'total_capacity_gb': 0,
                    'dimms': [],
                    'checked_at': datetime.now().isoformat(),
                    'method': 'dimm_info_check'
                }
            
            return {
                'status': 'error',
                'error': str(e),
                'dimm_count': 0,
                'total_capacity_gb': 0,
                'dimms': [],
                'checked_at': datetime.now().isoformat(),
                'method': 'dimm_info_check'
            }
    
    def _parse_dimm_output(self, output: str) -> Dict[str, Any]:
        """Parse the PowerShell output to extract DIMM information"""
        try:
            import json
            
            # Check for error conditions
            if "Error:" in output or not output or output == "null":
                return {
                    'status': 'error',
                    'error': 'No DIMM information found',
                    'dimm_count': 0,
                    'total_capacity_gb': 0,
                    'dimms': [],
                    'checked_at': datetime.now().isoformat(),
                    'method': 'dimm_info_check',
                    'raw_output': output
                }
            
            # Parse JSON output
            dimm_data = json.loads(output)
            
            # Handle single DIMM (not in array)
            if isinstance(dimm_data, dict):
                dimm_data = [dimm_data]
            
            dimms = []
            total_capacity_bytes = 0
            
            for dimm in dimm_data:
                capacity_bytes = int(dimm.get('Capacity', 0))
                capacity_gb = round(capacity_bytes / (1024**3), 2)  # Convert to GB
                total_capacity_bytes += capacity_bytes
                
                dimm_info = {
                    'bank_label': dimm.get('BankLabel', 'Unknown'),
                    'capacity_bytes': capacity_bytes,
                    'capacity_gb': capacity_gb,
                    'manufacturer': (dimm.get('Manufacturer') or 'Unknown').strip(),
                    'part_number': (dimm.get('PartNumber') or 'Unknown').strip(),
                    'speed_mhz': dimm.get('Speed', 0),
                    'serial_number': (dimm.get('SerialNumber') or 'Unknown').strip()
                }
                dimms.append(dimm_info)
            
            total_capacity_gb = round(total_capacity_bytes / (1024**3), 2)
            
            # Generate version string (summary of DIMM configuration)
            if dimms:
                # Group by manufacturer and part number to create a summary
                unique_types = {}
                for dimm in dimms:
                    key = f"{dimm['manufacturer']} {dimm['part_number']} {dimm['speed_mhz']}MHz"
                    if key not in unique_types:
                        unique_types[key] = []
                    unique_types[key].append(dimm)
                
                version_parts = []
                for dimm_type, dimm_list in unique_types.items():
                    count = len(dimm_list)
                    capacity = dimm_list[0]['capacity_gb']
                    version_parts.append(f"{count}x {capacity}GB {dimm_type}")
                
                version = " | ".join(version_parts)
            else:
                version = "NO_DIMMS_FOUND"
            
            return {
                'version': version,
                'status': 'success',
                'error': None,
                'dimm_count': len(dimms),
                'total_capacity_gb': total_capacity_gb,
                'dimms': dimms,
                'checked_at': datetime.now().isoformat(),
                'method': 'dimm_info_check',
                'raw_output': output
            }
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse DIMM JSON output: {e}")
            return {
                'status': 'error',
                'error': f'Failed to parse DIMM output: {str(e)}',
                'dimm_count': 0,
                'total_capacity_gb': 0,
                'dimms': [],
                'checked_at': datetime.now().isoformat(),
                'method': 'dimm_info_check',
                'raw_output': output
            }
        except Exception as e:
            logger.error(f"Error parsing DIMM output: {e}")
            return {
                'status': 'error',
                'error': f'Error parsing DIMM information: {str(e)}',
                'dimm_count': 0,
                'total_capacity_gb': 0,
                'dimms': [],
                'checked_at': datetime.now().isoformat(),
                'method': 'dimm_info_check',
                'raw_output': output if isinstance(output, str) else str(output)
            }
