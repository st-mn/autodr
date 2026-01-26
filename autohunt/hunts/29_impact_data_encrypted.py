#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Impact: Data Encrypted for Impact
Detects ransomware and data encryption attacks
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class DataEncryptedHunter:
    """Hunt for data encryption for impact (ransomware)"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_ransomware_indicators(self) -> List[Dict]:
        """Detect ransomware indicators"""
        findings = []
        
        ransomware_patterns = {
            'Encryption Tool': r'ransomware|encrypt.*file|file.*encrypt',
            'Ransom Note': r'ransom.*note|decrypt.*instruction',
            'File Extension Change': r'\.locked|\.encrypted|\.crypto',
            'Bulk Encryption': r'encrypt.*bulk|bulk.*encrypt'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for ransomware_type, pattern in ransomware_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Ransomware Indicator - {ransomware_type}',
                                    'line_number': line_num,
                                    'severity': 'CRITICAL',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting ransomware indicators: {e}")
        
        return findings
    
    def hunt_encryption_operations(self) -> List[Dict]:
        """Detect encryption operations"""
        findings = []
        
        encryption_patterns = {
            'OpenSSL Usage': r'openssl.*enc|openssl.*encrypt',
            'GPG Encryption': r'gpg.*encrypt|gpg.*-c',
            'Crypto Tools': r'cryptsetup|truecrypt|veracrypt',
            'Batch Encryption': r'for.*encrypt|encrypt.*loop'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for enc_type, pattern in encryption_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Encryption Operation - {enc_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting encryption operations: {e}")
        
        return findings
    
    def hunt_file_access_patterns(self) -> List[Dict]:
        """Detect suspicious file access patterns for encryption"""
        findings = []
        
        access_patterns = {
            'Rapid File Access': r'access.*rapid|rapid.*access|sequential.*file',
            'Shared Drive Access': r'share.*access|network.*drive.*access',
            'Database Access': r'database.*access|sql.*access',
            'Backup Access': r'backup.*access|backup.*location'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for access_type, pattern in access_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Suspicious File Access - {access_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting file access patterns: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_ransomware_indicators())
        self.findings.extend(self.hunt_encryption_operations())
        self.findings.extend(self.hunt_file_access_patterns())
        
        return {
            'tactic': 'Impact',
            'technique': 'Data Encrypted for Impact',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = DataEncryptedHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
