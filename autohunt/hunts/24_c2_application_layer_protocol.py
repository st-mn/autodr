#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Command and Control: Application Layer Protocol
Detects C2 communication over application layer protocols
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class ApplicationLayerC2Hunter:
    """Hunt for C2 communication over application layer protocols"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_http_c2(self) -> List[Dict]:
        """Detect HTTP/HTTPS C2 communication"""
        findings = []
        
        http_patterns = {
            'Suspicious User-Agent': r'User-Agent:.*(?:bot|crawler|scanner)',
            'Encoded Data': r'POST.*base64|GET.*base64',
            'Suspicious Headers': r'X-.*:.*[A-Za-z0-9+/=]{50,}',
            'Beacon Pattern': r'GET.*interval|POST.*check.*in'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for http_type, pattern in http_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'HTTP C2 - {http_type}',
                                    'line_number': line_num,
                                    'severity': 'CRITICAL',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting HTTP C2: {e}")
        
        return findings
    
    def hunt_dns_c2(self) -> List[Dict]:
        """Detect DNS-based C2 communication"""
        findings = []
        
        dns_patterns = {
            'DNS Tunneling': r'dns.*tunnel|tunnel.*dns',
            'Suspicious Queries': r'dns.*query.*unusual|query.*pattern',
            'Large Responses': r'dns.*response.*large|response.*size',
            'Subdomain Enumeration': r'dns.*subdomain|subdomain.*query'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for dns_type, pattern in dns_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'DNS C2 - {dns_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting DNS C2: {e}")
        
        return findings
    
    def hunt_email_c2(self) -> List[Dict]:
        """Detect email-based C2 communication"""
        findings = []
        
        email_patterns = {
            'Email Exfiltration': r'email.*exfil|exfil.*email',
            'Steganography': r'steganography|stego.*image',
            'Email Attachment': r'attachment.*command|command.*attachment',
            'Email Body Encoding': r'email.*base64|base64.*email'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for email_type, pattern in email_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Email C2 - {email_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting email C2: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_http_c2())
        self.findings.extend(self.hunt_dns_c2())
        self.findings.extend(self.hunt_email_c2())
        
        return {
            'tactic': 'Command and Control',
            'technique': 'Application Layer Protocol',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = ApplicationLayerC2Hunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
