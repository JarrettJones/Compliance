"""
OS Version Checker Module
Handles checking Windows OS version via WinRM
"""

import logging
import subprocess
import base64
import os
from datetime import datetime
from typing import Optional, Dict, Any

try:
    import winrm
    WINRM_AVAILABLE = True
except ImportError:
    WINRM_AVAILABLE = False
    winrm = None

logger = logging.getLogger(__name__)

class OSVersionChecker:
    """Checker for Windows OS version using registry query"""
    
    def __init__(self, os_username: Optional[str] = None, os_password: Optional[str] = None, timeout: int = 30):
        """
        Initialize OS Version checker
        
        Args:
            os_username: Username for WinRM authentication
            os_password: Password for WinRM authentication  
            timeout: Timeout for operations in seconds
        """
        self.os_username = os_username
        self.os_password = os_password
        self.timeout = timeout
    
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
    
    def get_os_version(self, computer_name: str) -> Dict[str, Any]:
        """
        Get Windows OS version information from registry
        
        Args:
            computer_name: The name or IP of the target computer
            
        Returns:
            Dictionary with OS version information
        """
        logger.info(f"Checking OS version on {computer_name}")
        
        # Check if the target computer is reachable via ping
        if not self.test_ping_ipv4(computer_name):
            logger.warning(f"Ping to {computer_name} failed. Computer is not reachable.")
            return {
                'version': 'HOST_UNREACHABLE',
                'status': 'error',
                'error': 'Host unreachable via ping',
                'checked_at': datetime.now().isoformat(),
                'method': 'os_version_check'
            }
        
        try:
            # PowerShell script to get OS version from registry
            ps_script = """
            try {
                $regPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\'
                $osInfo = Get-ItemProperty -Path $regPath -ErrorAction Stop
                
                if ($osInfo.BuildLabEx) {
                    Write-Output "BuildLabEx: $($osInfo.BuildLabEx)"
                    Write-Output "CurrentBuild: $($osInfo.CurrentBuild)"
                    Write-Output "CurrentVersion: $($osInfo.CurrentVersion)"
                    Write-Output "ProductName: $($osInfo.ProductName)"
                    Write-Output "DisplayVersion: $($osInfo.DisplayVersion)"
                    Write-Output "UBR: $($osInfo.UBR)"
                    Write-Output "BuildBranch: $($osInfo.BuildBranch)"
                } else {
                    Write-Output "Error: BuildLabEx not found in registry"
                }
            }
            catch {
                Write-Output "Error: Failed to get OS version - $_"
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
                        'version': 'NO_CREDENTIALS',
                        'status': 'error',
                        'error': 'Credentials required for remote connection',
                        'checked_at': datetime.now().isoformat(),
                        'method': 'os_version_check'
                    }
                
                if not WINRM_AVAILABLE:
                    return {
                        'version': 'WINRM_NOT_AVAILABLE',
                        'status': 'error',
                        'error': 'pywinrm module not installed',
                        'checked_at': datetime.now().isoformat(),
                        'method': 'os_version_check'
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
                        'method': 'os_version_check'
                    }
                
                output = result.std_out.decode('utf-8').strip()
            
            # Parse the output to extract OS version
            return self._parse_os_output(output)
            
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout while checking OS version on {computer_name}")
            return {
                'version': 'TIMEOUT_ERROR',
                'status': 'error',
                'error': f'Operation timed out after {self.timeout} seconds',
                'checked_at': datetime.now().isoformat(),
                'method': 'os_version_check'
            }
        except Exception as e:
            logger.error(f"Failed to check OS version on {computer_name}: {str(e)}")
            return {
                'version': 'EXCEPTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'os_version_check'
            }
    
    def _parse_os_output(self, output: str) -> Dict[str, Any]:
        """Parse the PowerShell output to extract OS version information"""
        try:
            lines = output.split('\n')
            os_info = {}
            
            # Parse output line by line
            for line in lines:
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    os_info[key.strip()] = value.strip()
            
            # Check for error conditions
            if "Error:" in output:
                error_msg = "Failed to retrieve OS version from registry"
                for line in lines:
                    if "Error:" in line:
                        error_msg = line.replace("Error:", "").strip()
                        break
                
                return {
                    'version': 'REGISTRY_ERROR',
                    'status': 'error',
                    'error': error_msg,
                    'checked_at': datetime.now().isoformat(),
                    'method': 'os_version_check',
                    'raw_output': output
                }
            
            # Extract BuildLabEx and filter to get OS version
            build_lab_ex = os_info.get('BuildLabEx', '')
            
            if not build_lab_ex:
                return {
                    'version': 'NOT_FOUND',
                    'status': 'error',
                    'error': 'BuildLabEx not found in registry output',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'os_version_check',
                    'raw_output': output
                }
            
            # Use the raw BuildLabEx as the version
            # This contains the full OS version information
            if build_lab_ex:
                return {
                    'version': build_lab_ex,
                    'status': 'success',
                    'error': None,
                    'checked_at': datetime.now().isoformat(),
                    'method': 'os_version_check',
                    'os_info': {
                        'build_lab_ex': build_lab_ex,
                        'current_build': os_info.get('CurrentBuild', ''),
                        'current_version': os_info.get('CurrentVersion', ''),
                        'product_name': os_info.get('ProductName', ''),
                        'display_version': os_info.get('DisplayVersion', ''),
                        'ubr': os_info.get('UBR', ''),
                        'build_branch': os_info.get('BuildBranch', '')
                    }
                }
            else:
                return {
                    'version': 'PARSE_ERROR',
                    'status': 'error',
                    'error': 'Could not parse OS version from BuildLabEx',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'os_version_check',
                    'raw_output': output
                }
                
        except Exception as e:
            logger.error(f"Error parsing OS output: {str(e)}")
            return {
                'version': 'PARSE_ERROR',
                'status': 'error',
                'error': f'Failed to parse OS output: {str(e)}',
                'checked_at': datetime.now().isoformat(),
                'method': 'os_version_check',
                'raw_output': output
            }
