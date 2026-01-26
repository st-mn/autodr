#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Execution: Command and Scripting Interpreter
Detects command execution and script interpretation activities
"""

import json
import re
import sys
import os
from datetime import datetime
from typing import Dict, List

class CommandScriptingHunter:
    """Hunt for command and scripting execution"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_powershell_execution(self) -> List[Dict]:
        """Detect suspicious PowerShell execution"""
        findings = []
        
        powershell_patterns = {
            'Encoded Commands': r'powershell.*-enc|-e\s+[A-Za-z0-9+/=]{50,}',
            'Hidden Window': r'-w\s+hidden|-windowstyle\s+hidden',
            'Bypass Policies': r'-exec.*bypass|executionpolicy.*bypass',
            'Download Execute': r'iex.*http|invoke-webrequest.*iex'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for ps_type, pattern in powershell_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'PowerShell Execution - {ps_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting PowerShell execution: {e}")
        
        return findings
    
    def hunt_bash_shell_execution(self) -> List[Dict]:
        """Detect suspicious bash/shell execution"""
        findings = []
        
        bash_patterns = {
            'Reverse Shell': r'bash\s+-i|/bin/bash.*-i|nc.*-e.*bash',
            'Command Substitution': r'\$\(.*\)|`.*`',
            'Pipe Chain': r'\|.*\|.*\|',
            'Background Execution': r'&\s*$|;\s*&'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for bash_type, pattern in bash_patterns.items():
                            if re.search(pattern, line):
                                findings.append({
                                    'type': f'Bash Execution - {bash_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting bash execution: {e}")
        
        return findings
    
    def hunt_script_execution(self) -> List[Dict]:
        """Detect script execution from suspicious sources"""
        findings = []
        
        script_patterns = {
            'Python Execution': r'python.*-c|python.*-m|exec\(.*\)',
            'JavaScript Execution': r'node.*-e|eval\(.*\)',
            'VBScript': r'cscript|wscript|vbscript',
            'Perl Execution': r'perl.*-e|perl.*-x'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for script_type, pattern in script_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Script Execution - {script_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting script execution: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_powershell_execution())
        self.findings.extend(self.hunt_bash_shell_execution())
        self.findings.extend(self.hunt_script_execution())
        
        return {
            'tactic': 'Execution',
            'technique': 'Command and Scripting Interpreter',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = CommandScriptingHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
