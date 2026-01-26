#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Reconnaissance: Phishing for Information
Detects phishing campaigns and social engineering attempts
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class PhishingInfoHunter:
    """Hunt for phishing and social engineering reconnaissance activities"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_phishing_emails(self) -> List[Dict]:
        """Detect phishing email indicators"""
        findings = []
        
        phishing_indicators = {
            'Urgent Action Required': r'urgent.*action|immediate.*response|act\s+now',
            'Credential Harvesting': r'verify.*account|confirm.*password|update.*credentials',
            'Spoofed Sender': r'From:.*@.*\.com.*(?:paypal|amazon|apple|microsoft)',
            'Malicious Links': r'href=.*bit\.ly|href=.*tinyurl|href=.*short\.link'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for indicator_type, pattern in phishing_indicators.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Phishing Email - {indicator_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting phishing emails: {e}")
        
        return findings
    
    def hunt_pretext_calls(self) -> List[Dict]:
        """Detect pretext calling and social engineering attempts"""
        findings = []
        
        pretext_patterns = [
            r'pretex.*call',
            r'social.*engineer',
            r'imperson.*IT|imperson.*support',
            r'verify.*identity|confirm.*employment'
        ]
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for pattern in pretext_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': 'Pretext Calling Detected',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting pretext calls: {e}")
        
        return findings
    
    def hunt_spearphishing_indicators(self) -> List[Dict]:
        """Detect spearphishing campaign indicators"""
        findings = []
        
        spearphishing_patterns = {
            'Personalization': r'Dear\s+\w+|Hello\s+\w+|Hi\s+\w+',
            'Executive Impersonation': r'CEO|CFO|CTO|President.*request',
            'Urgency': r'deadline|urgent|asap|immediate',
            'Authority': r'compliance|audit|investigation|legal.*review'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for attack_type, pattern in spearphishing_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Spearphishing - {attack_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting spearphishing: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_phishing_emails())
        self.findings.extend(self.hunt_pretext_calls())
        self.findings.extend(self.hunt_spearphishing_indicators())
        
        return {
            'tactic': 'Reconnaissance',
            'technique': 'Phishing for Information',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = PhishingInfoHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
