#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Execution: User Execution
Detects user-initiated execution of malicious files and content
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class UserExecutionHunter:
    """Hunt for user-initiated execution activities"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_malicious_file_execution(self) -> List[Dict]:
        """Detect execution of malicious files"""
        findings = []
        
        malicious_patterns = {
            'Double Extension': r'\.(txt|pdf|jpg)\.exe|\.(doc|xls)\.exe',
            'Suspicious Paths': r'(?:temp|tmp|appdata|windows\\system32)',
            'Hidden Files': r'(?:^|\s)\.[a-z0-9]+\.exe',
            'Unusual Extensions': r'\.scr|\.vbs|\.js|\.bat|\.cmd'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for file_type, pattern in malicious_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Malicious File Execution - {file_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting malicious file execution: {e}")
        
        return findings
    
    def hunt_macro_execution(self) -> List[Dict]:
        """Detect Office macro execution"""
        findings = []
        
        macro_patterns = {
            'Office Macro': r'\.docm|\.xlsm|\.pptm|\.odt.*macro',
            'Macro Enabled': r'macro.*enabled|macros.*allowed',
            'VBA Execution': r'vba.*execute|autoexec|document_open',
            'DDE Attack': r'dde\s+|dynamic.*data.*exchange'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for macro_type, pattern in macro_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Macro Execution - {macro_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting macro execution: {e}")
        
        return findings
    
    def hunt_browser_plugin_execution(self) -> List[Dict]:
        """Detect browser plugin and extension execution"""
        findings = []
        
        plugin_patterns = {
            'Flash Exploitation': r'flash.*exploit|swf.*malware',
            'Java Applet': r'java.*applet|\.jar.*execution',
            'Browser Extension': r'extension.*install|addon.*load',
            'ActiveX': r'activex|ocx.*load'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for plugin_type, pattern in plugin_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Plugin Execution - {plugin_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting plugin execution: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_malicious_file_execution())
        self.findings.extend(self.hunt_macro_execution())
        self.findings.extend(self.hunt_browser_plugin_execution())
        
        return {
            'tactic': 'Execution',
            'technique': 'User Execution',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = UserExecutionHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
