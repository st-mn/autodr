#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Collection: Input Capture
Detects keylogging and input capture activities
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class InputCaptureHunter:
    """Hunt for input capture activities"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_keylogger_installation(self) -> List[Dict]:
        """Detect keylogger installation"""
        findings = []
        
        keylogger_patterns = {
            'Keylogger Tool': r'keylogger|keystroke.*capture|capture.*keystroke',
            'Hook Installation': r'setwindowshook|keyboard.*hook',
            'Kernel Module': r'insmod.*keylog|kernel.*module.*key',
            'Library Injection': r'inject.*library|library.*inject'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for keylog_type, pattern in keylogger_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Keylogger Installation - {keylog_type}',
                                    'line_number': line_num,
                                    'severity': 'CRITICAL',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting keylogger installation: {e}")
        
        return findings
    
    def hunt_web_input_capture(self) -> List[Dict]:
        """Detect web form input capture"""
        findings = []
        
        web_patterns = {
            'Form Interception': r'form.*intercept|intercept.*form',
            'JavaScript Injection': r'javascript.*inject|inject.*javascript',
            'Password Field': r'password.*field.*capture|capture.*password',
            'Cookie Theft': r'cookie.*steal|steal.*cookie'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for web_type, pattern in web_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Web Input Capture - {web_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting web input capture: {e}")
        
        return findings
    
    def hunt_terminal_input_capture(self) -> List[Dict]:
        """Detect terminal input capture"""
        findings = []
        
        terminal_patterns = {
            'Shell Wrapper': r'bash.*wrapper|shell.*wrapper',
            'Command Logging': r'command.*log|log.*command',
            'Terminal Spy': r'terminal.*spy|spy.*terminal',
            'SSH Interception': r'ssh.*intercept|intercept.*ssh'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for terminal_type, pattern in terminal_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Terminal Input Capture - {terminal_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting terminal input capture: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_keylogger_installation())
        self.findings.extend(self.hunt_web_input_capture())
        self.findings.extend(self.hunt_terminal_input_capture())
        
        return {
            'tactic': 'Collection',
            'technique': 'Input Capture',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = InputCaptureHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
