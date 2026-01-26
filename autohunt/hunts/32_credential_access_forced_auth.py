#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Credential Access: Forced Authentication
Detects forced authentication and credential capture attempts
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class ForcedAuthenticationHunter:
    """Hunt for forced authentication activities"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_ntlm_relay(self) -> List[Dict]:
        """Detect NTLM relay attacks"""
        findings = []
        
        relay_patterns = {
            'NTLM Relay': r'ntlm.*relay|relay.*ntlm',
            'Responder Tool': r'responder|responder\.py',
            'LLMNR Poisoning': r'llmnr.*poison|poison.*llmnr',
            'NBT-NS Spoofing': r'nbt.*ns|netbios.*spoof'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for relay_type, pattern in relay_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'NTLM Relay - {relay_type}',
                                    'line_number': line_num,
                                    'severity': 'CRITICAL',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting NTLM relay: {e}")
        
        return findings
    
    def hunt_smb_capture(self) -> List[Dict]:
        """Detect SMB credential capture"""
        findings = []
        
        smb_patterns = {
            'SMB Signing Disabled': r'signing.*disabled|disable.*signing',
            'SMB Null Session': r'null.*session|anonymous.*smb',
            'Credential Capture': r'capture.*credential|credential.*capture',
            'NTLM Downgrade': r'ntlm.*downgrade|downgrade.*ntlm'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for smb_type, pattern in smb_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'SMB Capture - {smb_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting SMB capture: {e}")
        
        return findings
    
    def hunt_web_auth_capture(self) -> List[Dict]:
        """Detect web authentication capture"""
        findings = []
        
        web_patterns = {
            'Phishing Page': r'phishing.*page|fake.*login',
            'Auth Interception': r'intercept.*auth|man.*in.*middle',
            'Credential Prompt': r'credential.*prompt|password.*prompt',
            'SSL Strip': r'ssl.*strip|strip.*ssl'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for web_type, pattern in web_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Web Auth Capture - {web_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting web auth capture: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_ntlm_relay())
        self.findings.extend(self.hunt_smb_capture())
        self.findings.extend(self.hunt_web_auth_capture())
        
        return {
            'tactic': 'Credential Access',
            'technique': 'Forced Authentication',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = ForcedAuthenticationHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
