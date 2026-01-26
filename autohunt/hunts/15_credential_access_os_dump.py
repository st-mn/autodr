#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Credential Access: OS Credential Dumping
Detects credential dumping and extraction activities
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class CredentialDumpingHunter:
    """Hunt for OS credential dumping activities"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_lsass_dumping(self) -> List[Dict]:
        """Detect LSASS process dumping"""
        findings = []
        
        lsass_patterns = {
            'Process Dump': r'lsass.*dump|dump.*lsass|procdump.*lsass',
            'Mimikatz': r'mimikatz|sekurlsa|lsadump',
            'Direct Access': r'\\\.\\lsass|lsass.*memory',
            'WMI Dumping': r'wmi.*lsass|get-wmiobject.*lsass'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for dump_type, pattern in lsass_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'LSASS Dumping - {dump_type}',
                                    'line_number': line_num,
                                    'severity': 'CRITICAL',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting LSASS dumping: {e}")
        
        return findings
    
    def hunt_sam_registry_dump(self) -> List[Dict]:
        """Detect SAM registry dumping"""
        findings = []
        
        sam_patterns = {
            'SAM File Access': r'\\system32\\config\\sam|sam.*dump',
            'Registry Export': r'reg.*export.*sam|regedit.*sam',
            'Backup Copy': r'sam.*copy|copy.*sam',
            'Offline Dump': r'offline.*dump|sam.*extract'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for sam_type, pattern in sam_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'SAM Registry Dump - {sam_type}',
                                    'line_number': line_num,
                                    'severity': 'CRITICAL',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting SAM registry dump: {e}")
        
        return findings
    
    def hunt_ntds_dumping(self) -> List[Dict]:
        """Detect NTDS.dit dumping"""
        findings = []
        
        ntds_patterns = {
            'NTDS Access': r'ntds\.dit|ntds.*dump',
            'VSS Copy': r'vss.*copy|shadow.*copy.*ntds',
            'Volume Shadow Copy': r'vssadmin|diskshadow',
            'Domain Dump': r'domain.*dump|dcsync'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for ntds_type, pattern in ntds_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'NTDS Dumping - {ntds_type}',
                                    'line_number': line_num,
                                    'severity': 'CRITICAL',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting NTDS dumping: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_lsass_dumping())
        self.findings.extend(self.hunt_sam_registry_dump())
        self.findings.extend(self.hunt_ntds_dumping())
        
        return {
            'tactic': 'Credential Access',
            'technique': 'OS Credential Dumping',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = CredentialDumpingHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
