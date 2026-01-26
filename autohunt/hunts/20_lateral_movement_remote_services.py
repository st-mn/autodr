#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Lateral Movement: Remote Services
Detects lateral movement via remote services
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class RemoteServicesHunter:
    """Hunt for lateral movement via remote services"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_rdp_usage(self) -> List[Dict]:
        """Detect RDP lateral movement"""
        findings = []
        
        rdp_patterns = {
            'RDP Connection': r'mstsc|rdp.*connect|port.*3389',
            'RDP Logon': r'rdp.*logon|remote.*desktop.*connect',
            'Suspicious RDP': r'rdp.*admin|rdp.*system',
            'RDP Tools': r'psexec|pth-rdp|freerdp'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for rdp_type, pattern in rdp_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'RDP Usage - {rdp_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting RDP usage: {e}")
        
        return findings
    
    def hunt_ssh_lateral_movement(self) -> List[Dict]:
        """Detect SSH lateral movement"""
        findings = []
        
        ssh_patterns = {
            'SSH Connection': r'ssh\s+.*@|ssh.*-i|ssh.*-l',
            'SSH Key Usage': r'ssh.*key|private.*key.*ssh',
            'SSH Tunneling': r'ssh.*-L|ssh.*-R|ssh.*-D',
            'SCP Transfer': r'scp\s+|sftp\s+'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for ssh_type, pattern in ssh_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'SSH Lateral Movement - {ssh_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting SSH lateral movement: {e}")
        
        return findings
    
    def hunt_winrm_usage(self) -> List[Dict]:
        """Detect WinRM lateral movement"""
        findings = []
        
        winrm_patterns = {
            'WinRM Connection': r'winrm|invoke-command|new-pssession',
            'Remote Execution': r'invoke-command.*-computer|remote.*execution',
            'WinRM Port': r'port.*5985|port.*5986',
            'PSRemoting': r'enable-psremoting|disable-psremoting'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for winrm_type, pattern in winrm_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'WinRM Usage - {winrm_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting WinRM usage: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_rdp_usage())
        self.findings.extend(self.hunt_ssh_lateral_movement())
        self.findings.extend(self.hunt_winrm_usage())
        
        return {
            'tactic': 'Lateral Movement',
            'technique': 'Remote Services',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = RemoteServicesHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
