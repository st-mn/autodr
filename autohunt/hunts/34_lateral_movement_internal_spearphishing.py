#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Lateral Movement: Internal Spearphishing
Detects internal spearphishing campaigns for lateral movement
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class InternalSpearphishingHunter:
    """Hunt for internal spearphishing activities"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_internal_phishing(self) -> List[Dict]:
        """Detect internal phishing emails"""
        findings = []
        
        phishing_patterns = {
            'Spoofed Internal': r'From:.*@company\.com.*(?:unusual|suspicious)',
            'Urgent Request': r'urgent.*action|immediate.*approval',
            'Credential Request': r'verify.*credential|confirm.*password',
            'Malicious Link': r'href=.*(?:bit\.ly|tinyurl)'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for phish_type, pattern in phishing_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Internal Phishing - {phish_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting internal phishing: {e}")
        
        return findings
    
    def hunt_compromised_account_abuse(self) -> List[Dict]:
        """Detect abuse of compromised internal accounts"""
        findings = []
        
        abuse_patterns = {
            'Unusual Sender': r'email.*unusual|unusual.*sender',
            'Forwarding Rule': r'forwarding.*rule|mail.*rule.*create',
            'Bulk Sending': r'bulk.*email|email.*bulk',
            'Delegation': r'delegate.*access|grant.*access'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for abuse_type, pattern in abuse_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Compromised Account Abuse - {abuse_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting compromised account abuse: {e}")
        
        return findings
    
    def hunt_payload_delivery(self) -> List[Dict]:
        """Detect payload delivery via internal email"""
        findings = []
        
        payload_patterns = {
            'Malicious Attachment': r'attachment.*exe|attachment.*scr',
            'Macro Document': r'docm|xlsm|pptm',
            'Script Attachment': r'\.ps1|\.bat|\.vbs',
            'Archive Payload': r'zip.*password|rar.*password'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for payload_type, pattern in payload_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Payload Delivery - {payload_type}',
                                    'line_number': line_num,
                                    'severity': 'CRITICAL',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting payload delivery: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_internal_phishing())
        self.findings.extend(self.hunt_compromised_account_abuse())
        self.findings.extend(self.hunt_payload_delivery())
        
        return {
            'tactic': 'Lateral Movement',
            'technique': 'Internal Spearphishing',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = InternalSpearphishingHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
