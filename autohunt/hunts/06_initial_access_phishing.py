#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Initial Access: Phishing
Detects phishing attacks and malicious email delivery
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class PhishingHunter:
    """Hunt for phishing initial access attacks"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_malicious_attachments(self) -> List[Dict]:
        """Detect emails with malicious attachments"""
        findings = []
        
        malicious_extensions = {
            'Executable': r'\.(exe|dll|scr|vbs|js|bat|cmd|com|pif|msi)',
            'Office Macros': r'\.(docm|xlsm|pptm)',
            'Compressed': r'\.(zip|rar|7z).*(?:malware|payload|trojan)',
            'Scripts': r'\.(ps1|sh|bash|py|rb)'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for ext_type, pattern in malicious_extensions.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Malicious Attachment - {ext_type}',
                                    'line_number': line_num,
                                    'severity': 'CRITICAL',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting malicious attachments: {e}")
        
        return findings
    
    def hunt_phishing_urls(self) -> List[Dict]:
        """Detect phishing URLs in emails"""
        findings = []
        
        phishing_patterns = {
            'Credential Harvesting': r'login|signin|verify.*account|update.*payment',
            'Malware Distribution': r'download|click.*here|urgent.*update',
            'Shortened URLs': r'bit\.ly|tinyurl|short\.link|goo\.gl',
            'Suspicious Domains': r'(?:paypal|amazon|apple|microsoft)[-_]?[0-9]+\.'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for url_type, pattern in phishing_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Phishing URL - {url_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting phishing URLs: {e}")
        
        return findings
    
    def hunt_spearphishing_campaigns(self) -> List[Dict]:
        """Detect spearphishing campaign indicators"""
        findings = []
        
        campaign_patterns = {
            'Bulk Sending': r'bcc:.*(?:,.*){10,}|recipient.*count.*[0-9]{3,}',
            'Compromised Accounts': r'from:.*@(?:company|bank)\.com.*(?:unusual|suspicious)',
            'Template Injection': r'template.*injection|rtf.*exploit',
            'PDF Exploit': r'pdf.*exploit|adobe.*vulnerability'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for campaign_type, pattern in campaign_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Spearphishing Campaign - {campaign_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting spearphishing campaigns: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_malicious_attachments())
        self.findings.extend(self.hunt_phishing_urls())
        self.findings.extend(self.hunt_spearphishing_campaigns())
        
        return {
            'tactic': 'Initial Access',
            'technique': 'Phishing',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = PhishingHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
