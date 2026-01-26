#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Defense Evasion: Masquerading
Detects file and process masquerading activities
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class MasqueradingHunter:
    """Hunt for masquerading evasion techniques"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_file_masquerading(self) -> List[Dict]:
        """Detect file masquerading"""
        findings = []
        
        file_patterns = {
            'Double Extension': r'\.(txt|pdf|jpg|doc)\.exe|\.(doc|xls)\.scr',
            'Legitimate Name': r'(?:svchost|explorer|winlogon|services)\.exe.*(?:temp|appdata)',
            'Path Spoofing': r'C:\\Windows\\System32\\.*\.(txt|jpg|pdf)',
            'Icon Spoofing': r'icon.*change|change.*icon'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for file_type, pattern in file_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'File Masquerading - {file_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting file masquerading: {e}")
        
        return findings
    
    def hunt_process_masquerading(self) -> List[Dict]:
        """Detect process masquerading"""
        findings = []
        
        process_patterns = {
            'Legitimate Process Name': r'(?:svchost|explorer|services|lsass)\.exe.*(?:temp|appdata|downloads)',
            'Renamed Binary': r'renamed.*binary|binary.*rename',
            'Command Line Spoofing': r'(?:cmd|powershell).*fake.*argument',
            'Parent Process Spoofing': r'parent.*process.*spoof'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for proc_type, pattern in process_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Process Masquerading - {proc_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting process masquerading: {e}")
        
        return findings
    
    def hunt_system_masquerading(self) -> List[Dict]:
        """Detect system and service masquerading"""
        findings = []
        
        system_patterns = {
            'Service Masquerading': r'service.*create.*legitimate|fake.*service',
            'Driver Masquerading': r'driver.*masquerad|fake.*driver',
            'DLL Masquerading': r'dll.*masquerad|legitimate.*dll.*location',
            'Registry Spoofing': r'registry.*spoof|fake.*registry'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for sys_type, pattern in system_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'System Masquerading - {sys_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting system masquerading: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_file_masquerading())
        self.findings.extend(self.hunt_process_masquerading())
        self.findings.extend(self.hunt_system_masquerading())
        
        return {
            'tactic': 'Defense Evasion',
            'technique': 'Masquerading',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = MasqueradingHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
