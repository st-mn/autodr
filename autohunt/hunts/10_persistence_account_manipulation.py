#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Persistence: Account Manipulation
Detects unauthorized account creation and modification activities
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class AccountManipulationHunter:
    """Hunt for account manipulation persistence activities"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_unauthorized_account_creation(self) -> List[Dict]:
        """Detect unauthorized user account creation"""
        findings = []
        
        account_patterns = {
            'New User Creation': r'(?:useradd|net\s+user.*\/add|adduser)',
            'Hidden Account': r'useradd.*\$|hidden.*account|disabled.*logon',
            'Privileged Account': r'(?:admin|root|system).*create',
            'Service Account': r'service.*account.*create'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for account_type, pattern in account_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Unauthorized Account Creation - {account_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting unauthorized account creation: {e}")
        
        return findings
    
    def hunt_account_privilege_escalation(self) -> List[Dict]:
        """Detect account privilege escalation"""
        findings = []
        
        privilege_patterns = {
            'Group Addition': r'(?:net\s+localgroup|usermod.*-G|groupadd)',
            'Admin Promotion': r'(?:admin|administrator).*add|promote.*admin',
            'Domain Admin': r'domain.*admin.*add|enterprise.*admin',
            'Sudo Rights': r'sudoers.*edit|visudo|sudo.*nopasswd'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for priv_type, pattern in privilege_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Privilege Escalation - {priv_type}',
                                    'line_number': line_num,
                                    'severity': 'CRITICAL',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting privilege escalation: {e}")
        
        return findings
    
    def hunt_account_modification(self) -> List[Dict]:
        """Detect suspicious account modifications"""
        findings = []
        
        modification_patterns = {
            'Password Change': r'(?:passwd|password).*change|pwd.*modify',
            'Shell Change': r'chsh|usermod.*-s|shell.*change',
            'Home Directory': r'(?:homedir|home).*change|usermod.*-d',
            'Account Unlock': r'(?:unlock|enable).*account|account.*enabled'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for mod_type, pattern in modification_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Account Modification - {mod_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting account modification: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_unauthorized_account_creation())
        self.findings.extend(self.hunt_account_privilege_escalation())
        self.findings.extend(self.hunt_account_modification())
        
        return {
            'tactic': 'Persistence',
            'technique': 'Account Manipulation',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = AccountManipulationHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
