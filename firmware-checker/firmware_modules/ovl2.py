"""
OVL2 Firmware Checker Module
Handles checking firmware versions for OVL2 components
"""

import logging
import requests
import json
import re
import time
import socket
from datetime import datetime
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning
import urllib3
import paramiko
from .mana_driver import ManaDriverChecker

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)

class OVL2Checker:
    """Checker for OVL2 firmware components"""
    
    def __init__(self, username='admin', password='admin', timeout=30, os_username=None, os_password=None):
        # Default credentials - should be configurable
        self.username = username
        self.password = password
        self.timeout = timeout
        
        # OS credentials for MANA driver checks
        self.os_username = os_username
        self.os_password = os_password
        
        # Initialize MANA driver checker
        self.mana_checker = ManaDriverChecker(
            os_username=os_username,
            os_password=os_password,
            timeout=timeout
        )
        
        self.firmware_types = [
            'FPGA Agilex (App Image w/ OpRom)',
            'Cyclone V Image',
            'Cyclone V PFMID',
            'OVL SOC FIP',
            'OVL SOC FIP PFMID',
            'SOC Test OS (STOS)',
            'Host FPGA Driver & Tools',
            'SOC FPGA Driver',
            'MANA Driver (Windows)',
            'Glacier Cerberus FW',
            'Glacier Cerberus Utility',
            'Glacier Peak CFM'
        ]
    
    def check_all(self, rscm_ip, system_port=5, computer_name=None):
        """Check all OVL2 firmware versions using various methods
        
        Args:
            rscm_ip: RSCM IP address (e.g., 172.29.89.27)
            system_port: System port/slot number (e.g., 5) - this was rscm_port in the old system
            computer_name: Computer name for MANA driver checks (optional, defaults to rscm_ip)
        """
        logger.info(f"Checking OVL2 firmware for {rscm_ip}:{system_port}")
        print(f"[OVL2] Starting OVL2 firmware check for {rscm_ip}:{system_port}")
        
        results = {
            'category': 'OVL2',
            'timestamp': datetime.now().isoformat(),
            'rscm_ip': rscm_ip,
            'system_port': system_port,
            'status': 'success',
            'firmware_versions': {},
            'errors': []
        }
        
        try:
            # Check SOC Test OS using SSH serial session
            if 'SOC Test OS (STOS)' in self.firmware_types:
                print(f"[OVL2] Checking SOC Test OS via SSH serial session...")
                results['firmware_versions']['SOC Test OS (STOS)'] = self.check_soc_test_os(rscm_ip, system_port)
                print(f"[OVL2] SOC Test OS check completed")
            
            # Check Cyclone V Image using SSH serial session with fpgadiagnostics
            if 'Cyclone V Image' in self.firmware_types:
                print(f"[OVL2] Checking Cyclone V Image via SSH serial session...")
                results['firmware_versions']['Cyclone V Image'] = self.check_cyclone_v_image(rscm_ip, system_port)
                print(f"[OVL2] Cyclone V Image check completed")
            
            # Check Cyclone V PFMID using SSH serial session with cerberus_utility
            if 'Cyclone V PFMID' in self.firmware_types:
                print(f"[OVL2] Checking Cyclone V PFMID via SSH serial session...")
                results['firmware_versions']['Cyclone V PFMID'] = self.check_cyclone_v_pfmid(rscm_ip, system_port)
                print(f"[OVL2] Cyclone V PFMID check completed")
            
            # Check OVL SOC FIP PFMID using SSH serial session with cerberus_utility
            if 'OVL SOC FIP PFMID' in self.firmware_types:
                print(f"[OVL2] Checking OVL SOC FIP PFMID via SSH serial session...")
                results['firmware_versions']['OVL SOC FIP PFMID'] = self.check_ovl_soc_fip_pfmid(rscm_ip, system_port)
                print(f"[OVL2] OVL SOC FIP PFMID check completed")

            # Check OVL SOC FIP using SSH serial session with device-tree firmware version
            if 'OVL SOC FIP' in self.firmware_types:
                print(f"[OVL2] Checking OVL SOC FIP via SSH serial session...")
                results['firmware_versions']['OVL SOC FIP'] = self.check_ovl_soc_fip(rscm_ip, system_port)
                print(f"[OVL2] OVL SOC FIP check completed")

            # Check SOC FPGA Driver using SSH serial session with fpgadiagnostics -version
            if 'SOC FPGA Driver' in self.firmware_types:
                print(f"[OVL2] Checking SOC FPGA Driver via SSH serial session...")
                results['firmware_versions']['SOC FPGA Driver'] = self.check_soc_fpga_driver(rscm_ip, system_port)
                print(f"[OVL2] SOC FPGA Driver check completed")

            # Check MANA Driver (Windows) using WinRM if OS credentials are available
            if 'MANA Driver (Windows)' in self.firmware_types:
                if self.os_username and self.os_password and computer_name:
                    print(f"[OVL2] Checking MANA Driver on {computer_name} with OS credentials...")
                    results['firmware_versions']['MANA Driver (Windows)'] = self.mana_checker.get_mana_driver_version(computer_name)
                    print(f"[OVL2] MANA Driver check completed")
                else:
                    # No OS credentials or target computer - skip MANA driver check
                    skip_reason = "No OS credentials or computer name provided"
                    if not computer_name:
                        skip_reason = "No target computer specified for MANA driver check"
                    print(f"[OVL2] Skipping MANA driver check: {skip_reason}")
                    
                    results['firmware_versions']['MANA Driver (Windows)'] = {
                        'version': 'NOT_CHECKED',
                        'status': 'not_checked',
                        'error': skip_reason,
                        'checked_at': datetime.now().isoformat(),
                        'method': 'mana_driver_check'
                    }

            # Placeholder implementations for other firmware types
            remaining_types = [fw_type for fw_type in self.firmware_types if fw_type not in results['firmware_versions']]
            if remaining_types:
                print(f"[OVL2] Processing {len(remaining_types)} placeholder firmware types...")
            
            for fw_type in remaining_types:
                results['firmware_versions'][fw_type] = self._check_firmware_placeholder(fw_type, rscm_ip, system_port)
            
            if remaining_types:
                print(f"[OVL2] Placeholder firmware types completed")
        
        except Exception as e:
            logger.error(f"Error checking OVL2 firmware: {str(e)}")
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
    
    def _check_firmware_placeholder(self, firmware_type, rscm_ip, system_port):
        """Placeholder function for individual firmware checks"""
        print(f"[OVL2] Processing placeholder for: {firmware_type}")
        return {
            'version': 'PLACEHOLDER_VERSION',
            'status': 'not_implemented',
            'error': None,
            'checked_at': datetime.now().isoformat()
        }
    
    def check_fpga_agilex_app_image(self, rscm_ip, system_port):
        """Check FPGA Agilex App Image with OpRom version using SSH serial session with fpgadiagnostics
        
        This function connects to RSCM via SSH, starts a serial session to the specified port,
        and runs 'fpgadiagnostics -dumphealth -gpmc 0' to get the Agilex role_id and role_ver.
        
        Expected output format:
        [FPGA-CONFIG    ] OK [golden:0,role_id:0x4d565032,role_ver:0x1174009f,shell_id:0xca5cade,shell_ver:0x40004,sshell_id:0x20000,sshell_ver:0x3010037,crcerr:0,chngset:1292557145,verbmp:0,2023-3-28,clean:1,tfs:1]
        
        Args:
            rscm_ip: RSCM IP address
            system_port: System port/slot number for serial session
            
        Returns:
            Dictionary with FPGA Agilex App Image version information (role_id and role_ver)
        """
        try:
            logger.info(f"Starting FPGA Agilex App Image check via SSH serial session on {rscm_ip}:{system_port}")
            print(f"[OVL2] FPGA Agilex App Image: Connecting to RSCM via SSH...")
            
            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect to RSCM
            print(f"[OVL2] FPGA Agilex App Image: Establishing SSH connection to {rscm_ip}...")
            ssh.connect(
                hostname=rscm_ip,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                port=22
            )
            print(f"[OVL2] FPGA Agilex App Image: SSH connection established")
            
            # Create an interactive shell
            print(f"[OVL2] FPGA Agilex App Image: Creating interactive shell...")
            shell = ssh.invoke_shell()
            time.sleep(1)  # Wait for shell to be ready
            
            # Start serial session with -p 8295 parameter (like SOC methods)
            start_command = f"start serial session -i {system_port} -p 8295\n"
            logger.debug(f"Starting serial session for FPGA Agilex App Image: {start_command.strip()}")
            print(f"[OVL2] FPGA Agilex App Image: Starting serial session: {start_command.strip()}")
            shell.send(start_command)
            time.sleep(10)  # Allow time for command execution
            
            # Read output to check for "Completion Code: Failure"
            output = self._read_shell_output(shell)
            if "Completion Code: Failure" in output:
                ssh.close()
                return {
                    'version': 'SERIAL_SESSION_FAILED',
                    'status': 'error',
                    'error': 'Failed to start serial session - check connection',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_fpgadiagnostics_agilex'
                }
            
            # Send fpgadiagnostics command for Agilex
            fpga_command = "fpgadiagnostics -dumphealth -gpmc 0\n"
            logger.debug(f"[DEBUG] Sending FPGA Agilex command: {fpga_command.strip()}")
            print(f"[OVL2] [DEBUG] Sending command: {fpga_command.strip()}")
            shell.send(fpga_command)
            
            # Wait for command execution (longer for fpgadiagnostics)
            print(f"[OVL2] [DEBUG] Waiting 10 seconds for fpgadiagnostics execution...")
            time.sleep(10)
            
            # Read command output
            print(f"[OVL2] [DEBUG] Reading fpgadiagnostics output...")
            fpga_output = self._read_shell_output(shell)
            logger.debug(f"[DEBUG] FPGA Agilex raw output length: {len(fpga_output)} chars")
            logger.debug(f"[DEBUG] Raw output preview: {repr(fpga_output[:500])}")
            print(f"[OVL2] [DEBUG] Received {len(fpga_output)} characters of output")
            
            # Close connections
            print(f"[OVL2] [DEBUG] Closing SSH connections...")
            shell.close()
            ssh.close()
            
            # Parse the Agilex role_id and role_ver from output
            print(f"[OVL2] [DEBUG] Starting to parse FPGA Agilex version info...")
            version_info = self._parse_agilex_fpga_config(fpga_output)
            
            if version_info:
                logger.info(f"Successfully retrieved FPGA Agilex App Image info: {version_info}")
                return {
                    'version': version_info,
                    'status': 'success',
                    'error': None,
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_fpgadiagnostics_agilex',
                    'raw_output': fpga_output
                }
            else:
                logger.warning("Could not parse FPGA Agilex version info from output")
                return {
                    'version': 'AGILEX_CONFIG_NOT_FOUND',
                    'status': 'error',
                    'error': 'Could not find FPGA-CONFIG with role_id and role_ver in fpgadiagnostics output',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_fpgadiagnostics_agilex',
                    'raw_output': fpga_output
                }
                
        except paramiko.AuthenticationException:
            logger.error(f"SSH authentication failed for FPGA Agilex App Image check on {rscm_ip}")
            return {
                'version': 'SSH_AUTH_FAILED',
                'status': 'error',
                'error': 'SSH authentication failed',
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_fpgadiagnostics_agilex'
            }
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error for FPGA Agilex App Image check: {str(e)}")
            return {
                'version': 'SSH_CONNECTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_fpgadiagnostics_agilex'
            }
        except Exception as e:
            logger.error(f"Error checking FPGA Agilex App Image: {str(e)}")
            return {
                'version': 'EXCEPTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_fpgadiagnostics_agilex'
            }
    
    def check_cyclone_v_image(self, rscm_ip, system_port):
        """Check Cyclone V Image version using SSH serial session with fpgadiagnostics
        
        This function connects to RSCM via SSH, starts a serial session to the specified port,
        and runs 'fpgadiagnostics -dumphealth -gpmc 0' to get the Cyclone V shell version.
        
        Args:
            rscm_ip: RSCM IP address
            system_port: System port/slot number for serial session
            
        Returns:
            Dictionary with Cyclone V Image version information
        """
        try:
            logger.info(f"Starting Cyclone V Image check via SSH serial session on {rscm_ip}:{system_port}")
            print(f"[OVL2] Cyclone V Image: Connecting to RSCM via SSH...")
            
            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect to RSCM
            print(f"[OVL2] Cyclone V Image: Establishing SSH connection to {rscm_ip}...")
            ssh.connect(
                hostname=rscm_ip,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                port=22
            )
            print(f"[OVL2] Cyclone V Image: SSH connection established")
            
            # Create an interactive shell
            print(f"[OVL2] Cyclone V Image: Creating interactive shell...")
            shell = ssh.invoke_shell()
            time.sleep(1)  # Wait for shell to be ready
            
            # Start serial session with -b 1 parameter (different from SOC Test OS)
            start_command = f"start serial session -i {system_port} -b 1\n"
            logger.debug(f"Starting serial session for Cyclone V: {start_command.strip()}")
            shell.send(start_command)
            time.sleep(10)  # Allow time for command execution
            
            # Read output to check for "Completion Code: Failure"
            output = self._read_shell_output(shell)
            if "Completion Code: Failure" in output:
                ssh.close()
                return {
                    'version': 'SERIAL_SESSION_FAILED',
                    'status': 'error',
                    'error': 'Failed to start serial session - check connection',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_fpgadiagnostics'
                }
            
            # Run 'fpgadiagnostics -dumphealth -gpmc 0' command
            fpga_command = "fpgadiagnostics -dumphealth -gpmc 0\n"
            logger.debug(f"Getting Cyclone V info: {fpga_command.strip()}")
            shell.send(fpga_command)
            time.sleep(10)  # Allow time for command execution
            
            # Read the output
            fpga_output = self._read_shell_output(shell)
            logger.debug(f"Cyclone V fpgadiagnostics output: {fpga_output}")
            
            # Close SSH connection
            ssh.close()
            
            # Parse the shell_ver from fpgadiagnostics output
            cyclone_version = self._parse_cyclone_v_shell_version(fpga_output)
            
            if cyclone_version and cyclone_version != "CycloneVImage not found":
                return {
                    'version': cyclone_version,
                    'status': 'success',
                    'error': None,
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_fpgadiagnostics',
                    'raw_output': fpga_output
                }
            else:
                return {
                    'version': 'CYCLONE_VERSION_NOT_FOUND',
                    'status': 'error',
                    'error': 'Could not find CY5-CONFIG shell_ver in fpgadiagnostics output',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_fpgadiagnostics',
                    'raw_output': fpga_output
                }
                
        except paramiko.AuthenticationException:
            logger.error(f"SSH authentication failed for Cyclone V Image check on {rscm_ip}")
            return {
                'version': 'SSH_AUTH_FAILED',
                'status': 'error',
                'error': 'SSH authentication failed',
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_fpgadiagnostics'
            }
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error for Cyclone V Image check: {str(e)}")
            return {
                'version': 'SSH_CONNECTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_fpgadiagnostics'
            }
        except Exception as e:
            logger.error(f"Error checking Cyclone V Image: {str(e)}")
            return {
                'version': 'EXCEPTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_fpgadiagnostics'
            }
    
    def check_cyclone_v_pfmid(self, rscm_ip, system_port):
        """Check Cyclone V PFMID using SSH serial session with cerberus_utility
        
        This function connects to RSCM via SSH, starts a serial session to the specified port,
        and runs 'cerberus_utility pfmid 2 0' to get the Cyclone V PFM ID.
        
        Args:
            rscm_ip: RSCM IP address
            system_port: System port/slot number for serial session
            
        Returns:
            Dictionary with Cyclone V PFMID information
        """
        try:
            logger.info(f"Starting Cyclone V PFMID check via SSH serial session on {rscm_ip}:{system_port}")
            
            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect to RSCM
            ssh.connect(
                hostname=rscm_ip,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                port=22
            )
            
            # Create an interactive shell
            shell = ssh.invoke_shell()
            time.sleep(1)  # Wait for shell to be ready
            
            # Start serial session with -b 1 parameter (same as Cyclone V Image)
            start_command = f"start serial session -i {system_port} -b 1\n"
            logger.debug(f"Starting serial session for Cyclone V PFMID: {start_command.strip()}")
            shell.send(start_command)
            time.sleep(10)  # Allow time for command execution
            
            # Read output to check for "Completion Code: Failure"
            output = self._read_shell_output(shell)
            if "Completion Code: Failure" in output:
                ssh.close()
                return {
                    'version': 'SERIAL_SESSION_FAILED',
                    'status': 'error',
                    'error': 'Failed to start serial session - check connection',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_cerberus_utility'
                }
            
            # Run 'cerberus_utility pfmid 2 0' command
            cerberus_command = "cerberus_utility pfmid 2 0\n"
            logger.debug(f"Getting Cyclone V PFMID: {cerberus_command.strip()}")
            shell.send(cerberus_command)
            time.sleep(10)  # Allow time for command execution
            
            # Read the output
            cerberus_output = self._read_shell_output(shell)
            logger.debug(f"Cyclone V PFMID cerberus_utility output: {cerberus_output}")
            
            # Close SSH connection
            ssh.close()
            
            # Parse the PFM ID from cerberus_utility output
            pfm_id = self._parse_cyclone_v_pfm_id(cerberus_output)
            
            # Treat both hex PFM IDs and "No valid PFM found" messages as success (like CFM Platform ID)
            if pfm_id and pfm_id != "PFM ID not found":
                return {
                    'version': pfm_id,
                    'status': 'success',
                    'error': None,
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_cerberus_utility',
                    'raw_output': cerberus_output
                }
            else:
                return {
                    'version': 'PFM_ID_NOT_FOUND',
                    'status': 'error',
                    'error': 'Could not find Cerberus PFM ID in cerberus_utility output',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_cerberus_utility',
                    'raw_output': cerberus_output
                }
                
        except paramiko.AuthenticationException:
            logger.error(f"SSH authentication failed for Cyclone V PFMID check on {rscm_ip}")
            return {
                'version': 'SSH_AUTH_FAILED',
                'status': 'error',
                'error': 'SSH authentication failed',
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_cerberus_utility'
            }
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error for Cyclone V PFMID check: {str(e)}")
            return {
                'version': 'SSH_CONNECTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_cerberus_utility'
            }
        except Exception as e:
            logger.error(f"Error checking Cyclone V PFMID: {str(e)}")
            return {
                'version': 'EXCEPTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_cerberus_utility'
            }
    
    def check_ovl_soc_fip(self, rscm_ip, rscm_port=22):
        """Check OVL SOC FIP version"""
        # TODO: Implement actual OVL SOC FIP checking logic
        pass
    
    def check_ovl_soc_fip_pfmid(self, rscm_ip, system_port):
        """Check OVL SOC FIP PFMID using SSH serial session with cerberus_utility
        
        This function connects to RSCM via SSH, starts a serial session to the specified port,
        and runs 'cerberus_utility pfmid 0 0' to get the SOC PFM ID.
        
        Args:
            rscm_ip: RSCM IP address
            system_port: System port/slot number for serial session
            
        Returns:
            Dictionary with OVL SOC FIP PFMID information
        """
        try:
            logger.info(f"Starting OVL SOC FIP PFMID check via SSH serial session on {rscm_ip}:{system_port}")
            
            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect to RSCM
            ssh.connect(
                hostname=rscm_ip,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                port=22
            )
            
            # Create an interactive shell
            shell = ssh.invoke_shell()
            time.sleep(1)  # Wait for shell to be ready
            
            # Start serial session with -b 1 parameter (same as other serial sessions)
            start_command = f"start serial session -i {system_port} -b 1\n"
            logger.debug(f"Starting serial session for OVL SOC FIP PFMID: {start_command.strip()}")
            shell.send(start_command)
            time.sleep(10)  # Allow time for command execution
            
            # Read output to check for "Completion Code: Failure"
            output = self._read_shell_output(shell)
            if "Completion Code: Failure" in output:
                ssh.close()
                return {
                    'version': 'SERIAL_SESSION_FAILED',
                    'status': 'error',
                    'error': 'Failed to start serial session - check connection',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_cerberus_utility_soc'
                }
            
            # Run 'cerberus_utility pfmid 0 0' command (different parameters than Cyclone V)
            cerberus_command = "cerberus_utility pfmid 0 0\n"
            logger.debug(f"Getting OVL SOC FIP PFMID: {cerberus_command.strip()}")
            shell.send(cerberus_command)
            time.sleep(10)  # Allow time for command execution
            
            # Read the output
            cerberus_output = self._read_shell_output(shell)
            logger.debug(f"OVL SOC FIP PFMID cerberus_utility output: {cerberus_output}")
            
            # Close SSH connection
            ssh.close()
            
            # Parse the PFM ID from cerberus_utility output (same parsing as Cyclone V)
            pfm_id = self._parse_cyclone_v_pfm_id(cerberus_output)
            
            if pfm_id and pfm_id != "PFM ID not found":
                return {
                    'version': pfm_id,
                    'status': 'success',
                    'error': None,
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_cerberus_utility_soc',
                    'raw_output': cerberus_output
                }
            else:
                return {
                    'version': 'SOC_PFM_ID_NOT_FOUND',
                    'status': 'error',
                    'error': 'Could not find Cerberus PFM ID in cerberus_utility output',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_cerberus_utility_soc',
                    'raw_output': cerberus_output
                }
                
        except paramiko.AuthenticationException:
            logger.error(f"SSH authentication failed for OVL SOC FIP PFMID check on {rscm_ip}")
            return {
                'version': 'SSH_AUTH_FAILED',
                'status': 'error',
                'error': 'SSH authentication failed',
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_cerberus_utility_soc'
            }
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error for OVL SOC FIP PFMID check: {str(e)}")
            return {
                'version': 'SSH_CONNECTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_cerberus_utility_soc'
            }
        except Exception as e:
            logger.error(f"Error checking OVL SOC FIP PFMID: {str(e)}")
            return {
                'version': 'EXCEPTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_cerberus_utility_soc'
            }
    
    def check_ovl_soc_fip(self, rscm_ip, system_port):
        """Check OVL SOC FIP firmware using SSH serial session with device-tree version
        
        This function connects to RSCM via SSH, starts a serial session to the specified port,
        and runs 'cat /proc/device-tree/firmware/version' to get the SOC firmware version.
        
        Args:
            rscm_ip: RSCM IP address
            system_port: System port/slot number for serial session
            
        Returns:
            Dictionary with OVL SOC FIP firmware version information
        """
        try:
            logger.info(f"Starting OVL SOC FIP check via SSH serial session on {rscm_ip}:{system_port}")
            print(f"[OVL2] SOC FIP: Connecting to RSCM via SSH...")
            
            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect to RSCM
            print(f"[OVL2] SOC FIP: Establishing SSH connection to {rscm_ip}...")
            ssh.connect(
                hostname=rscm_ip,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                port=22
            )
            print(f"[OVL2] SOC FIP: SSH connection established")
            
            # Create an interactive shell
            print(f"[OVL2] SOC FIP: Creating interactive shell...")
            shell = ssh.invoke_shell()
            time.sleep(2)  # Wait for shell to be ready
            print(f"[OVL2] SOC FIP: Shell ready, starting serial session...")
            
            # Start serial session
            start_command = f"start serial session -i {system_port} -p 8295\n"
            logger.debug(f"Starting serial session: {start_command.strip()}")
            print(f"[OVL2] SOC FIP: Executing command: {start_command.strip()}")
            shell.send(start_command)
            print(f"[OVL2] SOC FIP: Waiting for serial session to start (10s)...")
            time.sleep(10)  # Allow time for command execution
            
            # Read output to check for "Completion Code: Failure"
            print(f"[OVL2] SOC FIP: Reading serial session output...")
            output = self._read_shell_output(shell)
            if "Completion Code: Failure" in output:
                print(f"[OVL2] SOC FIP: Serial session failed to start")
                ssh.close()
                return {
                    'version': 'SERIAL_SESSION_FAILED',
                    'status': 'error',
                    'error': 'Failed to start serial session - check connection',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session'
                }
            
            print(f"[OVL2] SOC FIP: Serial session started, running device-tree command...")
            # Run 'cat /proc/device-tree/firmware/version' command
            firmware_command = "cat /proc/device-tree/firmware/version\n"
            logger.debug(f"Getting SOC firmware version: {firmware_command.strip()}")
            shell.send(firmware_command)
            print(f"[OVL2] SOC FIP: Waiting for device-tree firmware output (10s)...")
            time.sleep(10)  # Allow time for command execution
            
            # Read the output
            print(f"[OVL2] SOC FIP: Reading device-tree firmware output...")
            firmware_output = self._read_shell_output(shell)
            logger.debug(f"SOC firmware output: {firmware_output}")
            
            # Close SSH connection
            print(f"[OVL2] SOC FIP: Closing SSH connection...")
            ssh.close()
            
            # Parse the firmware version from device-tree output
            firmware_version = self._parse_device_tree_firmware_version(firmware_output)
            
            if firmware_version and firmware_version != "SOC_Firmware not found":
                return {
                    'version': firmware_version,
                    'status': 'success',
                    'error': None,
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_device_tree',
                    'raw_output': firmware_output
                }
            else:
                return {
                    'version': 'SOC_FIRMWARE_NOT_FOUND',
                    'status': 'error',
                    'error': 'Could not find SOC firmware version in device-tree output',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_device_tree',
                    'raw_output': firmware_output
                }
                
        except paramiko.AuthenticationException:
            logger.error(f"SSH authentication failed for OVL SOC FIP check on {rscm_ip}")
            return {
                'version': 'SSH_AUTH_FAILED',
                'status': 'error',
                'error': 'SSH authentication failed',
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_device_tree'
            }
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error for OVL SOC FIP check: {str(e)}")
            return {
                'version': 'SSH_CONNECTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_device_tree'
            }
        except Exception as e:
            logger.error(f"Error checking OVL SOC FIP: {str(e)}")
            return {
                'version': 'EXCEPTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_device_tree'
            }
    
    def check_soc_fpga_driver(self, rscm_ip, system_port):
        """Check SOC FPGA Driver version using SSH serial session with fpgadiagnostics -version
        
        This function connects to RSCM via SSH, starts a serial session to the specified port,
        runs 'modprobe catapult' and then 'fpgadiagnostics -version' to get driver versions.
        
        Args:
            rscm_ip: RSCM IP address
            system_port: System port/slot number for serial session
            
        Returns:
            Dictionary with SOC FPGA Driver version information
        """
        try:
            logger.info(f"Starting SOC FPGA Driver check via SSH serial session on {rscm_ip}:{system_port}")
            print(f"[OVL2] SOC FPGA Driver: Connecting to RSCM via SSH...")
            
            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect to RSCM
            print(f"[OVL2] SOC FPGA Driver: Establishing SSH connection to {rscm_ip}...")
            ssh.connect(
                hostname=rscm_ip,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                port=22
            )
            print(f"[OVL2] SOC FPGA Driver: SSH connection established")
            
            # Create an interactive shell
            print(f"[OVL2] SOC FPGA Driver: Creating interactive shell...")
            shell = ssh.invoke_shell()
            time.sleep(2)  # Wait for shell to be ready
            print(f"[OVL2] SOC FPGA Driver: Shell ready, starting serial session...")
            
            # Start serial session
            start_command = f"start serial session -i {system_port} -p 8295\n"
            logger.debug(f"Starting serial session: {start_command.strip()}")
            print(f"[OVL2] SOC FPGA Driver: Executing command: {start_command.strip()}")
            shell.send(start_command)
            print(f"[OVL2] SOC FPGA Driver: Waiting for serial session to start (10s)...")
            time.sleep(10)  # Allow time for command execution
            
            # Read output to check for "Completion Code: Failure"
            print(f"[OVL2] SOC FPGA Driver: Reading serial session output...")
            output = self._read_shell_output(shell)
            if "Completion Code: Failure" in output:
                print(f"[OVL2] SOC FPGA Driver: Serial session failed to start")
                ssh.close()
                return {
                    'version': 'SERIAL_SESSION_FAILED',
                    'status': 'error',
                    'error': 'Failed to start serial session - check connection',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session'
                }
            
            # Run modprobe catapult command first
            print(f"[OVL2] SOC FPGA Driver: Loading catapult module...")
            modprobe_command = "modprobe catapult\n"
            shell.send(modprobe_command)
            time.sleep(10)  # Allow time for command execution
            
            print(f"[OVL2] SOC FPGA Driver: Running fpgadiagnostics -version...")
            # Run 'fpgadiagnostics -version' command
            fpga_command = "fpgadiagnostics -version\n"
            logger.debug(f"Getting FPGA driver versions: {fpga_command.strip()}")
            shell.send(fpga_command)
            print(f"[OVL2] SOC FPGA Driver: Waiting for fpgadiagnostics output (10s)...")
            time.sleep(10)  # Allow time for command execution
            
            # Read the output
            print(f"[OVL2] SOC FPGA Driver: Reading fpgadiagnostics output...")
            fpga_output = self._read_shell_output(shell)
            logger.debug(f"FPGA driver output: {fpga_output}")
            
            # Close SSH connection
            print(f"[OVL2] SOC FPGA Driver: Closing SSH connection...")
            ssh.close()
            
            # Parse the driver versions from fpgadiagnostics output
            driver_versions = self._parse_fpgadiagnostics_versions(fpga_output)
            
            if driver_versions:
                return {
                    'version': driver_versions,
                    'status': 'success',
                    'error': None,
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_fpgadiagnostics',
                    'raw_output': fpga_output
                }
            else:
                return {
                    'version': 'FPGA_DRIVERS_NOT_FOUND',
                    'status': 'error',
                    'error': 'Could not parse FPGA driver versions from output',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_fpgadiagnostics',
                    'raw_output': fpga_output
                }
                
        except paramiko.AuthenticationException:
            logger.error(f"SSH authentication failed for SOC FPGA Driver check on {rscm_ip}")
            return {
                'version': 'SSH_AUTH_FAILED',
                'status': 'error',
                'error': 'SSH authentication failed',
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_fpgadiagnostics'
            }
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error for SOC FPGA Driver check: {str(e)}")
            return {
                'version': 'SSH_CONNECTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_fpgadiagnostics'
            }
        except Exception as e:
            logger.error(f"Error checking SOC FPGA Driver: {str(e)}")
            return {
                'version': 'EXCEPTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_fpgadiagnostics'
            }
    
    def check_soc_test_os(self, rscm_ip, system_port):
        """Check SOC Test OS (STOS) version using SSH serial session
        
        This function connects to RSCM via SSH, starts a serial session to the specified port,
        and runs 'cat /etc/os-release' to get the VERSION_ID for SOC Test OS.
        
        Args:
            rscm_ip: RSCM IP address
            system_port: System port/slot number for serial session
            
        Returns:
            Dictionary with SOC Test OS version information
        """
        try:
            logger.info(f"Starting SOC Test OS check via SSH serial session on {rscm_ip}:{system_port}")
            print(f"[OVL2] SOC Test OS: Connecting to RSCM via SSH...")
            
            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect to RSCM
            print(f"[OVL2] SOC Test OS: Establishing SSH connection to {rscm_ip}...")
            ssh.connect(
                hostname=rscm_ip,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                port=22
            )
            print(f"[OVL2] SOC Test OS: SSH connection established")
            
            # Create an interactive shell
            print(f"[OVL2] SOC Test OS: Creating interactive shell...")
            shell = ssh.invoke_shell()
            time.sleep(2)  # Wait for shell to be ready
            print(f"[OVL2] SOC Test OS: Shell ready, starting serial session...")
            
            # Start serial session
            start_command = f"start serial session -i {system_port} -p 8295\n"
            logger.debug(f"Starting serial session: {start_command.strip()}")
            print(f"[OVL2] SOC Test OS: Executing command: {start_command.strip()}")
            shell.send(start_command)
            print(f"[OVL2] SOC Test OS: Waiting for serial session to start (10s)...")
            time.sleep(10)  # Allow time for command execution
            
            # Read output to check for "Completion Code: Failure"
            print(f"[OVL2] SOC Test OS: Reading serial session output...")
            output = self._read_shell_output(shell)
            if "Completion Code: Failure" in output:
                print(f"[OVL2] SOC Test OS: Serial session failed to start")
                ssh.close()
                return {
                    'version': 'SERIAL_SESSION_FAILED',
                    'status': 'error',
                    'error': 'Failed to start serial session - check connection',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session'
                }
            
            print(f"[OVL2] SOC Test OS: Serial session started, running os-release command...")
            # Run 'cat /etc/os-release' command
            os_release_command = "cat /etc/os-release\n"
            logger.debug(f"Getting SOC OS info: {os_release_command.strip()}")
            shell.send(os_release_command)
            print(f"[OVL2] SOC Test OS: Waiting for os-release output (10s)...")
            time.sleep(10)  # Allow time for command execution
            
            # Read the output
            print(f"[OVL2] SOC Test OS: Reading os-release output...")
            os_output = self._read_shell_output(shell)
            logger.debug(f"SOC OS output: {os_output}")
            
            # Close SSH connection
            print(f"[OVL2] SOC Test OS: Closing SSH connection...")
            ssh.close()
            
            # Parse the VERSION_ID from os-release output
            version_id = self._parse_version_id_from_os_release(os_output)
            
            # Always include the raw output for debugging
            logger.info(f"SOC Test OS raw output length: {len(os_output)} characters")
            logger.info(f"SOC Test OS raw output (first 500 chars): {os_output[:500]}")
            logger.info(f"SOC Test OS parsed VERSION_ID: '{version_id}'")
            
            if version_id and version_id != "SOC_OS not found":
                return {
                    'version': version_id,
                    'status': 'success',
                    'error': None,
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session',
                    'raw_output': os_output[:1000]  # Limit raw output size
                }
            else:
                return {
                    'version': 'VERSION_NOT_FOUND',
                    'status': 'error',
                    'error': f'Could not find VERSION_ID in /etc/os-release output. Raw output length: {len(os_output)} chars',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session',
                    'raw_output': os_output[:1000],  # Include raw output for debugging
                    'debug_info': f'Parsed result: "{version_id}"'
                }
                
        except paramiko.AuthenticationException:
            logger.error(f"SSH authentication failed for SOC Test OS check on {rscm_ip}")
            return {
                'version': 'SSH_AUTH_FAILED',
                'status': 'error',
                'error': 'SSH authentication failed',
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session'
            }
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error for SOC Test OS check: {str(e)}")
            return {
                'version': 'SSH_CONNECTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session'
            }
        except Exception as e:
            logger.error(f"Error checking SOC Test OS: {str(e)}")
            return {
                'version': 'EXCEPTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session'
            }
    
    def check_host_fpga_driver_tools(self, rscm_ip, rscm_port=22):
        """Check Host FPGA Driver & Tools version"""
        # TODO: Implement actual Host FPGA Driver & Tools checking logic
        pass
    

    
    def check_mana_driver_windows(self, rscm_ip, rscm_port=22):
        """Check MANA Driver (Windows) version"""
        # TODO: Implement actual MANA Driver checking logic
        pass
    
    def check_glacier_cerberus_fw(self, rscm_ip, system_port):
        """Check Glacier Cerberus FW version using SSH serial session with cerberus_utility
        
        Based on PowerShell SerialSessionMBCerberus function:
        1. Establishes SSH connection to RSCM
        2. Starts serial session with 'start serial session -i {system_port} -b 1' 
        3. Runs 'cerberus_utility fwver' to get firmware version
        4. Parses output for 'Cerberus Version : {version}' pattern
        
        Args:
            rscm_ip (str): IP address of the RSCM
            system_port (int): System port/slot number for serial session
            
        Returns:
            dict: Result with version, status, method, and debug info
        """
        
        try:
            logger.info(f"Starting Glacier Cerberus FW check via SSH serial session on {rscm_ip}:{system_port}")
            print(f"[OVL2] Glacier Cerberus FW: Connecting to RSCM via SSH...")
            
            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect to RSCM
            print(f"[OVL2] Glacier Cerberus FW: Establishing SSH connection to {rscm_ip}...")
            ssh.connect(
                hostname=rscm_ip,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                port=22
            )
            print(f"[OVL2] Glacier Cerberus FW: SSH connection established")
            
            # Create an interactive shell
            print(f"[OVL2] Glacier Cerberus FW: Creating interactive shell...")
            shell = ssh.invoke_shell()
            time.sleep(1)  # Wait for shell to be ready
            
            # Start serial session with -b 1 parameter (same as Cyclone V methods)
            start_command = f"start serial session -i {system_port} -b 1\n"
            logger.debug(f"Starting serial session for Glacier Cerberus FW: {start_command.strip()}")
            print(f"[OVL2] Glacier Cerberus FW: Starting serial session: {start_command.strip()}")
            shell.send(start_command)
            time.sleep(10)  # Allow time for command execution
            
            # Read output to check for "Completion Code: Failure"
            output = self._read_shell_output(shell)
            if "Completion Code: Failure" in output:
                ssh.close()
                return {
                    'version': 'SERIAL_SESSION_FAILED',
                    'status': 'error',
                    'error': 'Failed to start serial session - check connection',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_cerberus_utility'
                }
            
            # Send cerberus_utility fwver command (shorter version)
            cerberus_command = "cerberus_utility fwversion\n"
            logger.debug(f"[DEBUG] Sending Cerberus FW command: {cerberus_command.strip()}")
            print(f"[OVL2] [DEBUG] Sending command: {cerberus_command.strip()}")
            shell.send(cerberus_command)
            
            # Wait for command execution
            print(f"[OVL2] [DEBUG] Waiting 5 seconds for command execution...")
            time.sleep(5)
            
            # Read command output
            print(f"[OVL2] [DEBUG] Reading command output...")
            cerberus_output = self._read_shell_output(shell)
            logger.debug(f"[DEBUG] Glacier Cerberus FW raw output length: {len(cerberus_output)} chars")
            logger.debug(f"[DEBUG] Raw output: {repr(cerberus_output)}")
            print(f"[OVL2] [DEBUG] Received {len(cerberus_output)} characters of output")
            
            # Close connections
            print(f"[OVL2] [DEBUG] Closing SSH connections...")
            shell.close()
            ssh.close()
            
            # Parse the Cerberus version from output
            print(f"[OVL2] [DEBUG] Starting to parse Cerberus version...")
            version = self._parse_cerberus_fw_version(cerberus_output)
            
            if version:
                logger.info(f"Successfully retrieved Glacier Cerberus FW version: {version}")
                return {
                    'version': version,
                    'status': 'success',
                    'error': None,
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_cerberus_utility',
                    'raw_output': cerberus_output
                }
            else:
                logger.warning("Could not parse Cerberus FW version from output")
                return {
                    'version': 'CERBERUS_VERSION_NOT_FOUND',
                    'status': 'error',
                    'error': 'Could not find Cerberus Version in cerberus_utility output',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_cerberus_utility',
                    'raw_output': cerberus_output
                }
                
        except paramiko.AuthenticationException:
            logger.error(f"SSH authentication failed for Glacier Cerberus FW check on {rscm_ip}")
            return {
                'version': 'SSH_AUTH_FAILED',
                'status': 'error',
                'error': 'SSH authentication failed',
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_cerberus_utility'
            }
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error for Glacier Cerberus FW check: {str(e)}")
            return {
                'version': 'SSH_CONNECTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_cerberus_utility'
            }
        except Exception as e:
            logger.error(f"Error checking Glacier Cerberus FW: {str(e)}")
            return {
                'version': 'EXCEPTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_cerberus_utility'
            }
    
    def check_glacier_cerberus_utility(self, rscm_ip, system_port):
        """Check Glacier Cerberus Utility version using SSH serial session with cerberus_utility
        
        This function connects to RSCM via SSH, starts a serial session to the specified port,
        and runs 'cerberus_utility version' to get the utility version.
        
        Expected output format:
        root@localhost:~# cerberus_utility version
        --------------------------------------------------------------------------------
        -------------------- Cerberus Utility Version: 1.4.12.1 -------------------------
        --------------------------------------------------------------------------------
        
        
        Cerberus command completed successfully.
        
        Args:
            rscm_ip: RSCM IP address
            system_port: System port/slot number for serial session
            
        Returns:
            Dictionary with Glacier Cerberus Utility version information
        """
        try:
            logger.info(f"Starting Glacier Cerberus Utility check via SSH serial session on {rscm_ip}:{system_port}")
            print(f"[OVL2] Glacier Cerberus Utility: Connecting to RSCM via SSH...")
            
            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect to RSCM
            print(f"[OVL2] Glacier Cerberus Utility: Establishing SSH connection to {rscm_ip}...")
            ssh.connect(
                hostname=rscm_ip,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                port=22
            )
            print(f"[OVL2] Glacier Cerberus Utility: SSH connection established")
            
            # Create an interactive shell
            print(f"[OVL2] Glacier Cerberus Utility: Creating interactive shell...")
            shell = ssh.invoke_shell()
            time.sleep(1)  # Wait for shell to be ready
            
            # Start serial session with -b 1 parameter (same as other Cerberus methods)
            start_command = f"start serial session -i {system_port} -b 1\n"
            logger.debug(f"Starting serial session for Glacier Cerberus Utility: {start_command.strip()}")
            print(f"[OVL2] Glacier Cerberus Utility: Starting serial session: {start_command.strip()}")
            shell.send(start_command)
            time.sleep(10)  # Allow time for command execution
            
            # Read output to check for "Completion Code: Failure"
            output = self._read_shell_output(shell)
            if "Completion Code: Failure" in output:
                ssh.close()
                return {
                    'version': 'SERIAL_SESSION_FAILED',
                    'status': 'error',
                    'error': 'Failed to start serial session - check connection',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_cerberus_utility_version'
                }
            
            # Send cerberus_utility version command
            cerberus_command = "cerberus_utility version\n"
            logger.debug(f"[DEBUG] Sending Cerberus Utility version command: {cerberus_command.strip()}")
            print(f"[OVL2] [DEBUG] Sending command: {cerberus_command.strip()}")
            shell.send(cerberus_command)
            
            # Wait for command execution
            print(f"[OVL2] [DEBUG] Waiting 5 seconds for command execution...")
            time.sleep(5)
            
            # Read command output
            print(f"[OVL2] [DEBUG] Reading command output...")
            cerberus_output = self._read_shell_output(shell)
            logger.debug(f"[DEBUG] Glacier Cerberus Utility raw output length: {len(cerberus_output)} chars")
            logger.debug(f"[DEBUG] Raw output: {repr(cerberus_output)}")
            print(f"[OVL2] [DEBUG] Received {len(cerberus_output)} characters of output")
            
            # Close connections
            print(f"[OVL2] [DEBUG] Closing SSH connections...")
            shell.close()
            ssh.close()
            
            # Parse the Cerberus utility version from output
            print(f"[OVL2] [DEBUG] Starting to parse Cerberus utility version...")
            version = self._parse_cerberus_utility_version(cerberus_output)
            
            if version:
                logger.info(f"Successfully retrieved Glacier Cerberus Utility version: {version}")
                return {
                    'version': version,
                    'status': 'success',
                    'error': None,
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_cerberus_utility_version',
                    'raw_output': cerberus_output
                }
            else:
                logger.warning("Could not parse Cerberus Utility version from output")
                return {
                    'version': 'CERBERUS_UTILITY_VERSION_NOT_FOUND',
                    'status': 'error',
                    'error': 'Could not find Cerberus Utility Version in cerberus_utility version output',
                    'checked_at': datetime.now().isoformat(),
                    'method': 'ssh_serial_session_cerberus_utility_version',
                    'raw_output': cerberus_output
                }
                
        except paramiko.AuthenticationException:
            logger.error(f"SSH authentication failed for Glacier Cerberus Utility check on {rscm_ip}")
            return {
                'version': 'SSH_AUTH_FAILED',
                'status': 'error',
                'error': 'SSH authentication failed',
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_cerberus_utility_version'
            }
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error for Glacier Cerberus Utility check: {str(e)}")
            return {
                'version': 'SSH_CONNECTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_cerberus_utility_version'
            }
        except Exception as e:
            logger.error(f"Error checking Glacier Cerberus Utility: {str(e)}")
            return {
                'version': 'EXCEPTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'ssh_serial_session_cerberus_utility_version'
            }
    
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
        
        logger.debug(f"Starting to read shell output (timeout: {timeout}s)")
        print(f"[OVL2] Reading shell output (timeout: {timeout}s)...")
        
        while time.time() - start_time < timeout:
            if shell.recv_ready():
                try:
                    chunk = shell.recv(8192).decode('utf-8', errors='ignore')
                    if chunk:
                        output += chunk
                        last_data_time = time.time()
                        logger.debug(f"Received {len(chunk)} chars, total: {len(output)}")
                        # Show progress every 5 seconds or when significant data is received
                        if len(output) % 1000 < len(chunk) or (time.time() - start_time) % 5 < 0.1:
                            elapsed = time.time() - start_time
                            print(f"[OVL2] Shell output progress: {len(output)} chars received ({elapsed:.1f}s elapsed)")
                except Exception as e:
                    logger.warning(f"Error reading shell chunk: {e}")
                    print(f"[OVL2] Warning: Error reading shell chunk: {e}")
                    break
            else:
                # If no data available, wait a bit
                time.sleep(0.1)
                
                # If we haven't received data for 5 seconds, try a longer wait
                if time.time() - last_data_time > 5:
                    time.sleep(1)
                    
                    # If still no data after 10 seconds since last data, consider done
                    if time.time() - last_data_time > 10:
                        logger.debug(f"No data received for 10 seconds, considering complete")
                        break
                
        logger.debug(f"Finished reading shell output: {len(output)} characters")
        return output
    
    def _parse_version_id_from_os_release(self, output):
        """Parse VERSION_ID from /etc/os-release output
        
        Args:
            output: Raw output from 'cat /etc/os-release' command
            
        Returns:
            VERSION_ID value or "SOC_OS not found" if not found
        """
        try:
            logger.debug(f"Parsing VERSION_ID from output (length: {len(output)})")
            
            # Normalize line endings and split into lines
            output = output.replace('\r\n', '\n').replace('\r', '\n')
            lines = output.split('\n')
            
            logger.debug(f"Split into {len(lines)} lines")
            
            # Look for VERSION_ID line with multiple patterns
            for i, line in enumerate(lines):
                line_stripped = line.strip()
                logger.debug(f"Line {i}: '{line_stripped[:100]}{'...' if len(line_stripped) > 100 else ''}'")
                
                # Pattern 1: Standard VERSION_ID=value
                if line_stripped.startswith('VERSION_ID='):
                    match = re.match(r'^\s*VERSION_ID=\s*(.+?)\s*$', line_stripped)
                    if match:
                        version_value = match.group(1).strip()
                        # Remove quotes if present
                        version_value = version_value.strip('"\'')
                        logger.info(f"Found VERSION_ID (pattern 1): '{version_value}'")
                        return version_value
                
                # Pattern 2: Look for VERSION_ID anywhere in the line (case insensitive)
                version_match = re.search(r'VERSION_ID\s*=\s*(["\']?)([^"\'\\s]+)\1', line_stripped, re.IGNORECASE)
                if version_match:
                    version_value = version_match.group(2).strip()
                    logger.info(f"Found VERSION_ID (pattern 2): '{version_value}'")
                    return version_value
                
                # Pattern 3: Look for any line containing "version" and a number pattern
                if re.search(r'version', line_stripped, re.IGNORECASE):
                    version_match = re.search(r'(\d+\.\d+(?:\.\d+)*)', line_stripped)
                    if version_match:
                        version_value = version_match.group(1)
                        logger.info(f"Found version pattern (pattern 3): '{version_value}'")
                        return version_value
            
            logger.warning(f"VERSION_ID not found in {len(lines)} lines of os-release output")
            logger.debug(f"Full output for debugging: {repr(output[:500])}")
            return "SOC_OS not found"
            
        except Exception as e:
            logger.error(f"Error parsing VERSION_ID from os-release: {str(e)}")
            logger.debug(f"Error occurred with output: {repr(output[:200])}")
            return "SOC_OS not found"
    
    def _parse_cyclone_v_shell_version(self, output):
        """Parse Cyclone V shell version from fpgadiagnostics output
        
        Args:
            output: Raw output from 'fpgadiagnostics -dumphealth -gpmc 0' command
            
        Returns:
            Shell version string or "CycloneVImage not found" if not found
        """
        try:
            # Normalize line endings and split into lines
            output = output.replace('\r\n', '\n').replace('\r', '\n')
            lines = output.split('\n')
            
            # Look for [CY5-CONFIG ] line with shell_ver pattern
            # Example: [CY5-CONFIG     ] OK [board:EV1] [shell_ver:0.18.4,chngset:0x85d27da6,clean:1]
            for line in lines:
                line = line.strip()
                logger.debug(f"Checking line for CY5-CONFIG: {repr(line[:100])}")
                
                # Check if line contains CY5-CONFIG
                if 'CY5-CONFIG' in line:
                    logger.debug(f"Found CY5-CONFIG line: {line}")
                    
                    # Pattern: [CY5-CONFIG ].*shell_ver:version with flexible spacing
                    # Match shell_ver:X.X.X where version can have dots and numbers
                    match = re.search(r'shell_ver:\s*([0-9]+\.[0-9]+\.[0-9]+)', line)
                    if match:
                        version_value = match.group(1).strip()
                        logger.info(f"Found Cyclone V shell_ver: {version_value}")
                        return version_value
                    else:
                        logger.warning(f"CY5-CONFIG line found but shell_ver pattern not matched: {line}")
            
            logger.warning("CY5-CONFIG shell_ver not found in fpgadiagnostics output")
            return "CycloneVImage not found"
            
        except Exception as e:
            logger.error(f"Error parsing Cyclone V shell version: {str(e)}")
            return "CycloneVImage not found"
    
    def _parse_cyclone_v_pfm_id(self, output):
        """Parse Cyclone V PFM ID from cerberus_utility output
        
        Args:
            output: Raw output from 'cerberus_utility pfmid 2 0' command
            
        Returns:
            PFM ID string (e.g., "0x12345678") or actual error message from cerberus
        """
        try:
            # Normalize line endings and split into lines
            output = output.replace('\r\n', '\n').replace('\r', '\n')
            lines = output.split('\n')
            
            # Look for "Cerberus PFM ID:" line with hex value (successful case)
            for line in lines:
                line = line.strip()
                # Pattern: Cerberus PFM ID: 0x{hex_value}
                match = re.match(r'.*Cerberus PFM ID:\s*(0x[0-9a-fA-F]+)', line)
                if match:
                    pfm_id_value = match.group(1).strip()
                    logger.debug(f"Found Cyclone V PFM ID: {pfm_id_value}")
                    return pfm_id_value
            
            # Look for "No valid PFM found" messages (like CFM Platform ID does)
            for line in lines:
                line = line.strip()
                if "No valid PFM found" in line:
                    logger.debug(f"Found Cyclone V PFM not found message: {line}")
                    return line  # Return the actual message like "No valid PFM found for port 2, region 0"
            
            logger.warning("Cerberus PFM ID not found in cerberus_utility output")
            return "PFM ID not found"
            
        except Exception as e:
            logger.error(f"Error parsing Cyclone V PFM ID: {str(e)}")
            return "PFM ID not found"
    
    def _parse_cerberus_fw_version(self, output):
        """Parse Cerberus FW version from cerberus_utility fwversion output
        
        Expected output format:
        --------------------------------------------------------------------------------
        -------------------- Cerberus Utility Version: 1.4.12.1 -------------------------
        --------------------------------------------------------------------------------
        
        Cerberus Version: 2.4.11.3
        
        Cerberus command completed successfully.
        root@localhost:~#
        
        Args:
            output: Raw output from 'cerberus_utility fwversion' command
            
        Returns:
            Cerberus version string or None if not found
        """
        try:
            logger.debug(f"[DEBUG] Raw cerberus_utility fwversion output length: {len(output)} chars")
            logger.debug(f"[DEBUG] Raw output preview (first 500 chars): {repr(output[:500])}")
            print(f"[OVL2] [DEBUG] Parsing Cerberus output, length: {len(output)} chars")
            
            # Normalize line endings and split into lines
            output = output.replace('\r\n', '\n').replace('\r', '\n')
            lines = output.split('\n')
            
            logger.debug(f"[DEBUG] Split into {len(lines)} lines")
            print(f"[OVL2] [DEBUG] Split into {len(lines)} lines for parsing")
            
            # Debug: Print each line with line number
            for i, line in enumerate(lines):
                line_clean = line.strip()
                if line_clean:  # Only log non-empty lines
                    logger.debug(f"[DEBUG] Line {i:2d}: '{line_clean}'")
                    print(f"[OVL2] [DEBUG] Line {i:2d}: '{line_clean}'")
            
            # Look for "Cerberus Version: {version}" line (note: colon, not space-colon)
            for i, line in enumerate(lines):
                line = line.strip()
                
                # Try multiple patterns to match the version line
                patterns = [
                    r'^Cerberus Version:\s*(.+)$',           # Exact match: "Cerberus Version: X.X.X.X"
                    r'.*Cerberus Version:\s*(.+)',          # Anywhere in line
                    r'^Cerberus Version\s*:\s*(.+)$',       # With optional space before colon
                    r'.*Cerberus Version\s*:\s*(.+)'        # Anywhere with optional space
                ]
                
                for pattern in patterns:
                    match = re.match(pattern, line, re.IGNORECASE)
                    if match:
                        version = match.group(1).strip()
                        logger.debug(f"[DEBUG] FOUND! Pattern '{pattern}' matched line {i}: '{line}'")
                        logger.debug(f"[DEBUG] Extracted version: '{version}'")
                        print(f"[OVL2] [DEBUG] SUCCESS! Found Cerberus version: '{version}' on line {i}")
                        return version
            
            # If we get here, no version was found
            logger.warning("[DEBUG] Cerberus Version not found in any line")
            logger.warning(f"[DEBUG] Full output for analysis: {repr(output)}")
            print(f"[OVL2] [DEBUG] ERROR: Cerberus Version not found in cerberus_utility output")
            print(f"[OVL2] [DEBUG] Expected pattern: 'Cerberus Version: X.X.X.X'")
            return None
            
        except Exception as e:
            logger.error(f"[DEBUG] Exception parsing Cerberus FW version: {str(e)}")
            print(f"[OVL2] [DEBUG] Exception during parsing: {str(e)}")
            return None
    
    def _parse_cerberus_utility_version(self, output):
        """Parse Cerberus Utility version from cerberus_utility version output
        
        Expected output format:
        root@localhost:~# cerberus_utility version
        --------------------------------------------------------------------------------
        -------------------- Cerberus Utility Version: 1.4.12.1 -------------------------
        --------------------------------------------------------------------------------
        
        
        Cerberus command completed successfully.
        
        Args:
            output: Raw output from 'cerberus_utility version' command
            
        Returns:
            Cerberus utility version string or None if not found
        """
        try:
            logger.debug(f"[DEBUG] Raw cerberus_utility version output length: {len(output)} chars")
            logger.debug(f"[DEBUG] Raw output preview (first 500 chars): {repr(output[:500])}")
            print(f"[OVL2] [DEBUG] Parsing Cerberus utility output, length: {len(output)} chars")
            
            # Normalize line endings and split into lines
            output = output.replace('\r\n', '\n').replace('\r', '\n')
            lines = output.split('\n')
            
            logger.debug(f"[DEBUG] Split into {len(lines)} lines")
            print(f"[OVL2] [DEBUG] Split into {len(lines)} lines for parsing")
            
            # Debug: Print each line with line number
            for i, line in enumerate(lines):
                line_clean = line.strip()
                if line_clean:  # Only log non-empty lines
                    logger.debug(f"[DEBUG] Line {i:2d}: '{line_clean}'")
                    print(f"[OVL2] [DEBUG] Line {i:2d}: '{line_clean}'")
            
            # Look for "Cerberus Utility Version: {version}" line
            for i, line in enumerate(lines):
                line = line.strip()
                
                # Try multiple patterns to match the utility version line
                patterns = [
                    r'^.*Cerberus Utility Version:\s*(.+?)\s*-*\s*$',  # Extract version from dashed line
                    r'.*Cerberus Utility Version:\s*(.+)',            # Anywhere in line
                    r'^.*Version:\s*(\d+\.\d+\.\d+\.\d+)',           # Any "Version:" with number pattern
                    r'.*Version:\s*(\d+\.\d+\.\d+\.\d+)'             # Version with number pattern anywhere
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        version = match.group(1).strip()
                        # Remove any trailing dashes or decorative characters
                        version = re.sub(r'[-\s]+$', '', version)
                        logger.debug(f"[DEBUG] FOUND! Pattern '{pattern}' matched line {i}: '{line}'")
                        logger.debug(f"[DEBUG] Extracted utility version: '{version}'")
                        print(f"[OVL2] [DEBUG] SUCCESS! Found Cerberus utility version: '{version}' on line {i}")
                        return version
            
            # If we get here, no version was found
            logger.warning("[DEBUG] Cerberus Utility Version not found in any line")
            logger.warning(f"[DEBUG] Full output for analysis: {repr(output)}")
            print(f"[OVL2] [DEBUG] ERROR: Cerberus Utility Version not found in cerberus_utility output")
            print(f"[OVL2] [DEBUG] Expected pattern: 'Cerberus Utility Version: X.X.X.X'")
            return None
            
        except Exception as e:
            logger.error(f"[DEBUG] Exception parsing Cerberus Utility version: {str(e)}")
            print(f"[OVL2] [DEBUG] Exception during parsing: {str(e)}")
            return None
    
    def _parse_device_tree_firmware_version(self, output):
        """Parse SOC firmware version from device-tree output
        
        Args:
            output: Raw output from 'cat /proc/device-tree/firmware/version' command
            
        Returns:
            Firmware version string or "SOC_Firmware not found" if not found
        """
        try:
            # Normalize line endings and split into lines
            output = output.replace('\r\n', '\n').replace('\r', '\n')
            lines = output.split('\n')
            
            # Remove empty lines and strip whitespace
            clean_lines = [line.strip() for line in lines if line.strip()]
            
            # Filter out command lines and system prompts
            firmware_lines = []
            for line in clean_lines:
                # Skip lines that look like commands, prompts, or status messages
                if not (line.startswith('admin@') or 
                       line.startswith('$') or 
                       'cat /proc/device-tree' in line or
                       line.endswith('~$') or
                       'Command completed' in line or
                       'Firmware version information' in line):
                    firmware_lines.append(line)
            
            # According to PowerShell function, capture the next-to-last line of filtered output
            if len(firmware_lines) >= 2:
                firmware_version = firmware_lines[-2].strip()
                logger.debug(f"Found SOC firmware version: {firmware_version}")
                return firmware_version
            elif len(firmware_lines) == 1:
                firmware_version = firmware_lines[0].strip()
                logger.debug(f"Found SOC firmware version (single line): {firmware_version}")
                return firmware_version
            else:
                logger.warning("No firmware version found in device-tree output")
                return "SOC_Firmware not found"
                
        except Exception as e:
            logger.error(f"Error parsing device-tree firmware version: {str(e)}")
            return "SOC_Firmware not found"
    
    def _parse_fpgadiagnostics_versions(self, output):
        """Parse FPGA driver versions from fpgadiagnostics -version output
        
        Args:
            output: Raw output from 'fpgadiagnostics -version' command
            
        Returns:
            Dictionary with driver versions or None if not found
        """
        try:
            # Normalize line endings and split into lines
            output = output.replace('\r\n', '\n').replace('\r', '\n')
            lines = output.split('\n')
            
            driver_versions = {}
            
            # Extract driver versions based on PowerShell patterns
            for line in lines:
                line = line.strip()
                
                # Look for patterns like "fpgadiagnostics: 1.2.3"
                if re.match(r'^fpgadiagnostics:\s*(.+)$', line):
                    match = re.match(r'^fpgadiagnostics:\s*(.+)$', line)
                    driver_versions["fpgadiagnostics"] = match.group(1).strip()
                elif re.match(r'^corelib:\s*(.+)$', line):
                    match = re.match(r'^corelib:\s*(.+)$', line)
                    driver_versions["corelib"] = match.group(1).strip()
                elif re.match(r'^hipdriver:\s*(.+)$', line):
                    match = re.match(r'^hipdriver:\s*(.+)$', line)
                    driver_versions["hipdriver"] = match.group(1).strip()
                elif re.match(r'^filter:\s*(.+)$', line):
                    match = re.match(r'^filter:\s*(.+)$', line)
                    driver_versions["filter"] = match.group(1).strip()
            
            if driver_versions:
                logger.debug(f"Found FPGA driver versions: {driver_versions}")
                # Return as a formatted string similar to other firmware versions
                version_strings = []
                for driver, version in driver_versions.items():
                    version_strings.append(f"{driver}: {version}")
                return "; ".join(version_strings)
            else:
                logger.warning("No FPGA driver versions found in fpgadiagnostics output")
                return None
                
        except Exception as e:
            logger.error(f"Error parsing fpgadiagnostics versions: {str(e)}")
            return None
    
    def _parse_agilex_fpga_config(self, output):
        """Parse FPGA Agilex role_id and role_ver from fpgadiagnostics -dumphealth -gpmc 0 output
        
        Expected line format:
        [FPGA-CONFIG    ] OK [golden:0,role_id:0x4d565032,role_ver:0x1174009f,shell_id:0xca5cade,shell_ver:0x40004,sshell_id:0x20000,sshell_ver:0x3010037,crcerr:0,chngset:1292557145,verbmp:0,2023-3-28,clean:1,tfs:1]
        
        Args:
            output: Raw output from 'fpgadiagnostics -dumphealth -gpmc 0' command
            
        Returns:
            String with role_id and role_ver info or None if not found
        """
        try:
            logger.debug(f"[DEBUG] Raw fpgadiagnostics Agilex output length: {len(output)} chars")
            logger.debug(f"[DEBUG] Raw output preview (first 500 chars): {repr(output[:500])}")
            print(f"[OVL2] [DEBUG] Parsing FPGA Agilex output, length: {len(output)} chars")
            
            # Normalize line endings and split into lines
            output = output.replace('\r\n', '\n').replace('\r', '\n')
            lines = output.split('\n')
            
            logger.debug(f"[DEBUG] Split into {len(lines)} lines")
            print(f"[OVL2] [DEBUG] Split into {len(lines)} lines for parsing")
            
            # Look for [FPGA-CONFIG] line with role_id and role_ver
            for i, line in enumerate(lines):
                line_clean = line.strip()
                logger.debug(f"[DEBUG] Line {i:2d}: '{line_clean[:100]}{'...' if len(line_clean) > 100 else ''}'")
                
                # Look for FPGA-CONFIG line
                if '[FPGA-CONFIG' in line_clean and 'OK' in line_clean:
                    print(f"[OVL2] [DEBUG] Found FPGA-CONFIG line {i}: {line_clean}")
                    
                    # Extract role_id and role_ver using regex
                    role_id_match = re.search(r'role_id:(0x[0-9a-fA-F]+)', line_clean)
                    role_ver_match = re.search(r'role_ver:(0x[0-9a-fA-F]+)', line_clean)
                    
                    if role_id_match and role_ver_match:
                        role_id = role_id_match.group(1)
                        role_ver = role_ver_match.group(1)
                        version_info = f"role_id:{role_id}, role_ver:{role_ver}"
                        
                        logger.debug(f"[DEBUG] FOUND! Extracted role_id: {role_id}, role_ver: {role_ver}")
                        print(f"[OVL2] [DEBUG] SUCCESS! Found FPGA Agilex info: {version_info}")
                        return version_info
                    else:
                        logger.debug(f"[DEBUG] FPGA-CONFIG line found but missing role_id or role_ver")
                        print(f"[OVL2] [DEBUG] FPGA-CONFIG line found but missing role_id or role_ver")
            
            # If we get here, no FPGA-CONFIG line was found
            logger.warning("[DEBUG] FPGA-CONFIG line not found in fpgadiagnostics output")
            print(f"[OVL2] [DEBUG] ERROR: FPGA-CONFIG line not found in fpgadiagnostics output")
            return None
            
        except Exception as e:
            logger.error(f"[DEBUG] Exception parsing FPGA Agilex config: {str(e)}")
            print(f"[OVL2] [DEBUG] Exception during parsing: {str(e)}")
            return None
    
    def set_credentials(self, username, password):
        """Set authentication credentials for SSH connections"""
        self.username = username
        self.password = password
    
    def check_glacier_peak_cfm(self, rscm_ip, rscm_port=22):
        """Check Glacier Peak CFM version"""
        # TODO: Implement actual Glacier Peak CFM checking logic
        pass
    
    def check_individual_firmware(self, firmware_type, rscm_ip, system_port=5, computer_name=None):
        """Check individual firmware type with detailed progress
        
        Args:
            firmware_type: Name of the firmware type to check
            rscm_ip: RSCM IP address
            system_port: System port/slot number
            computer_name: Computer name for MANA driver checks (optional)
            
        Returns:
            Dictionary with firmware version information
        """
        print(f"[OVL2] Checking individual firmware: {firmware_type}")
        
        try:
            # Map firmware types to their checking methods
            if firmware_type == 'SOC Test OS (STOS)':
                return self.check_soc_test_os(rscm_ip, system_port)
            elif firmware_type == 'Cyclone V Image':
                return self.check_cyclone_v_image(rscm_ip, system_port)
            elif firmware_type == 'Cyclone V PFMID':
                return self.check_cyclone_v_pfmid(rscm_ip, system_port)
            elif firmware_type == 'OVL SOC FIP PFMID':
                return self.check_ovl_soc_fip_pfmid(rscm_ip, system_port)
            elif firmware_type == 'OVL SOC FIP':
                return self.check_ovl_soc_fip(rscm_ip, system_port)
            elif firmware_type == 'SOC FPGA Driver':
                return self.check_soc_fpga_driver(rscm_ip, system_port)
            elif firmware_type == 'Glacier Cerberus FW':
                return self.check_glacier_cerberus_fw(rscm_ip, system_port)
            elif firmware_type == 'Glacier Cerberus Utility':
                return self.check_glacier_cerberus_utility(rscm_ip, system_port)
            elif firmware_type == 'FPGA Agilex (App Image w/ OpRom)':
                return self.check_fpga_agilex_app_image(rscm_ip, system_port)
            elif firmware_type == 'MANA Driver (Windows)':
                if self.os_username and self.os_password and computer_name:
                    return self.mana_checker.get_mana_driver_version(computer_name)
                else:
                    # No OS credentials or target computer - skip MANA driver check
                    skip_reason = "No OS credentials or computer name provided"
                    if not computer_name:
                        skip_reason = "No target computer specified for MANA driver check"
                    
                    return {
                        'version': 'NOT_CHECKED',
                        'status': 'not_checked',
                        'error': skip_reason,
                        'checked_at': datetime.now().isoformat(),
                        'method': 'mana_driver_check'
                    }
            else:
                return self._check_firmware_placeholder(firmware_type, rscm_ip, system_port)
        
        except Exception as e:
            logger.error(f"Error checking individual OVL2 firmware {firmware_type}: {str(e)}")
            return {
                'version': 'EXCEPTION_ERROR',
                'status': 'error',
                'error': str(e),
                'checked_at': datetime.now().isoformat(),
                'method': 'individual_check'
            }