#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Command and Control: Remote Access Tools
Detects remote access tool usage for C2
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class RemoteAccessToolsHunter:
    """Hunt for remote access tool usage"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_rat_indicators(self) -> List[Dict]:
        """Detect RAT indicators"""
        findings = []
        
        rat_patterns = {
            'Cobalt Strike': r'cobalt.*strike|beacon|malleable',
            'Metasploit': r'metasploit|meterpreter',
            'Empire': r'powershell.*empire|empire.*agent',
            'AsyncRAT': r'asyncrat|async.*rat'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for rat_type, pattern in rat_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'RAT Indicator - {rat_type}',
                                    'line_number': line_num,
                                    'severity': 'CRITICAL',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting RAT indicators: {e}")
        
        return findings
    
    def hunt_remote_desktop_tools(self) -> List[Dict]:
        """Detect remote desktop tool usage"""
        findings = []
        
        rdp_patterns = {
            'TeamViewer': r'teamviewer|teamviewer.*connection',
            'AnyDesk': r'anydesk|anydesk.*session',
            'Chrome Remote': r'chrome.*remote|remote.*desktop',
            'VNC': r'vnc.*connect|vnc.*session'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for tool_type, pattern in rdp_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Remote Desktop Tool - {tool_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting remote desktop tools: {e}")
        
        return findings
    
    def hunt_reverse_shell(self) -> List[Dict]:
        """Detect reverse shell indicators"""
        findings = []
        
        shell_patterns = {
            'Bash Reverse': r'bash\s+-i.*\/dev\/tcp|bash.*reverse',
            'Python Reverse': r'python.*socket|python.*reverse',
            'Netcat': r'nc\s+-e|netcat.*-e',
            'PowerShell Reverse': r'powershell.*reverse|reverse.*powershell'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for shell_type, pattern in shell_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Reverse Shell - {shell_type}',
                                    'line_number': line_num,
                                    'severity': 'CRITICAL',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting reverse shell: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_rat_indicators())
        self.findings.extend(self.hunt_remote_desktop_tools())
        self.findings.extend(self.hunt_reverse_shell())
        
        return {
            'tactic': 'Command and Control',
            'technique': 'Remote Access Tools',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = RemoteAccessToolsHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
