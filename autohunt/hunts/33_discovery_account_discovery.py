#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Discovery: Account Discovery
Detects account enumeration and discovery activities
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class AccountDiscoveryHunter:
    """Hunt for account discovery activities"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_local_account_enumeration(self) -> List[Dict]:
        """Detect local account enumeration"""
        findings = []
        
        enum_patterns = {
            'Net User': r'net\s+user|Get-LocalUser|id\s+.*user',
            'Passwd File': r'cat\s+/etc/passwd|getent\s+passwd',
            'User Listing': r'lusrmgr|user.*list',
            'Group Enumeration': r'net\s+group|Get-LocalGroup'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for enum_type, pattern in enum_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Local Account Enumeration - {enum_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting local account enumeration: {e}")
        
        return findings
    
    def hunt_domain_account_enumeration(self) -> List[Dict]:
        """Detect domain account enumeration"""
        findings = []
        
        domain_patterns = {
            'AD Query': r'Get-ADUser|dsquery.*user',
            'Net Domain': r'net\s+user.*\/domain|net\s+group.*\/domain',
            'LDAP Query': r'ldapsearch|ldap.*query',
            'Domain Enumeration': r'domain.*enum|enum.*domain'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for domain_type, pattern in domain_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Domain Account Enumeration - {domain_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting domain account enumeration: {e}")
        
        return findings
    
    def hunt_privileged_account_discovery(self) -> List[Dict]:
        """Detect privileged account discovery"""
        findings = []
        
        priv_patterns = {
            'Admin Discovery': r'(?:admin|administrator).*enum|enum.*admin',
            'Root User': r'root.*user|uid.*0',
            'Service Account': r'service.*account|system.*account',
            'Domain Admin': r'domain.*admin|enterprise.*admin'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for priv_type, pattern in priv_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Privileged Account Discovery - {priv_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting privileged account discovery: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_local_account_enumeration())
        self.findings.extend(self.hunt_domain_account_enumeration())
        self.findings.extend(self.hunt_privileged_account_discovery())
        
        return {
            'tactic': 'Discovery',
            'technique': 'Account Discovery',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = AccountDiscoveryHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
