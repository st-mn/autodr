#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Impact: Data Destruction
Detects data destruction and deletion activities
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class DataDestructionHunter:
    """Hunt for data destruction activities"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_file_deletion(self) -> List[Dict]:
        """Detect suspicious file deletion"""
        findings = []
        
        deletion_patterns = {
            'Bulk Delete': r'rm\s+-rf|del\s+/s|rmdir\s+/s',
            'Recursive Delete': r'delete.*recursive|recursive.*delete',
            'Secure Delete': r'shred|srm|secure.*delete',
            'Wipe Command': r'wipe|overwrite.*file|file.*overwrite'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for delete_type, pattern in deletion_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'File Deletion - {delete_type}',
                                    'line_number': line_num,
                                    'severity': 'CRITICAL',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting file deletion: {e}")
        
        return findings
    
    def hunt_log_deletion(self) -> List[Dict]:
        """Detect log file deletion or clearing"""
        findings = []
        
        log_patterns = {
            'Log Clearing': r'clear.*log|log.*clear|truncate.*log',
            'Event Log': r'event.*log.*delete|delete.*event.*log',
            'Syslog': r'syslog.*delete|delete.*syslog',
            'History Deletion': r'history.*delete|delete.*history|history.*clear'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for log_type, pattern in log_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Log Deletion - {log_type}',
                                    'line_number': line_num,
                                    'severity': 'CRITICAL',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting log deletion: {e}")
        
        return findings
    
    def hunt_backup_destruction(self) -> List[Dict]:
        """Detect backup and recovery destruction"""
        findings = []
        
        backup_patterns = {
            'Shadow Copy Delete': r'vssadmin.*delete|delete.*shadow.*copy',
            'Backup Deletion': r'delete.*backup|backup.*delete',
            'Recovery Destruction': r'recovery.*destroy|destroy.*recovery',
            'VSS Disable': r'vss.*disable|disable.*vss'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for backup_type, pattern in backup_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Backup Destruction - {backup_type}',
                                    'line_number': line_num,
                                    'severity': 'CRITICAL',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting backup destruction: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_file_deletion())
        self.findings.extend(self.hunt_log_deletion())
        self.findings.extend(self.hunt_backup_destruction())
        
        return {
            'tactic': 'Impact',
            'technique': 'Data Destruction',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = DataDestructionHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
