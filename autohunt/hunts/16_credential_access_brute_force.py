#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Credential Access: Brute Force
Detects brute force attacks and password guessing attempts
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class BruteForceHunter:
    """Hunt for brute force credential access attacks"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_ssh_brute_force(self) -> List[Dict]:
        """Detect SSH brute force attacks"""
        findings = []
        
        ssh_patterns = {
            'Failed Logins': r'invalid.*user|authentication.*failure|failed.*password',
            'Multiple Attempts': r'(?:failed|invalid).*(?:failed|invalid).*(?:failed|invalid)',
            'Port Scanning': r'ssh.*port.*scan|port.*22.*attempt',
            'Credential Stuffing': r'multiple.*user.*attempt|user.*enumeration'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for ssh_type, pattern in ssh_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'SSH Brute Force - {ssh_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting SSH brute force: {e}")
        
        return findings
    
    def hunt_http_brute_force(self) -> List[Dict]:
        """Detect HTTP/HTTPS brute force attacks"""
        findings = []
        
        http_patterns = {
            'Login Attempts': r'POST.*login|POST.*auth|401.*unauthorized',
            'Rapid Requests': r'(?:401|403).*(?:401|403).*(?:401|403)',
            'Credential Stuffing': r'multiple.*password|password.*attempt',
            'API Brute Force': r'api.*auth|api.*login.*failed'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for http_type, pattern in http_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'HTTP Brute Force - {http_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting HTTP brute force: {e}")
        
        return findings
    
    def hunt_password_spray(self) -> List[Dict]:
        """Detect password spray attacks"""
        findings = []
        
        spray_patterns = {
            'Multiple Users': r'multiple.*user.*attempt|user.*enumeration',
            'Common Passwords': r'password123|admin|letmein|welcome',
            'Distributed Attack': r'multiple.*source|distributed.*attack',
            'Account Lockout': r'account.*locked|lockout.*threshold'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for spray_type, pattern in spray_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Password Spray - {spray_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting password spray: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_ssh_brute_force())
        self.findings.extend(self.hunt_http_brute_force())
        self.findings.extend(self.hunt_password_spray())
        
        return {
            'tactic': 'Credential Access',
            'technique': 'Brute Force',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = BruteForceHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
