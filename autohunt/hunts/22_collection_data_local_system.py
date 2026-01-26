#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Collection: Data from Local System
Detects data collection from local systems
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class DataLocalSystemHunter:
    """Hunt for data collection from local systems"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_file_collection(self) -> List[Dict]:
        """Detect file collection activities"""
        findings = []
        
        collection_patterns = {
            'File Search': r'find\s+.*-name|dir\s+/s|locate\s+',
            'File Copying': r'cp\s+.*\.txt|copy\s+.*\.doc|xcopy',
            'Archive Creation': r'tar\s+-czf|zip\s+-r|rar\s+a',
            'File Staging': r'staging.*directory|temp.*collect'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for collect_type, pattern in collection_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'File Collection - {collect_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting file collection: {e}")
        
        return findings
    
    def hunt_sensitive_data_access(self) -> List[Dict]:
        """Detect access to sensitive data"""
        findings = []
        
        sensitive_patterns = {
            'Config Files': r'\.conf|\.config|\.cfg|\.ini',
            'Credential Files': r'\.ssh|\.aws|\.azure|\.kube',
            'Database Files': r'\.db|\.sqlite|\.mdb',
            'Source Code': r'\.git|\.svn|\.hg|source.*code'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for data_type, pattern in sensitive_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Sensitive Data Access - {data_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting sensitive data access: {e}")
        
        return findings
    
    def hunt_browser_data_collection(self) -> List[Dict]:
        """Detect browser data collection"""
        findings = []
        
        browser_patterns = {
            'Browser History': r'history|cookies|cache',
            'Browser Credentials': r'browser.*password|saved.*password',
            'Browser Extensions': r'extension.*data|addon.*data',
            'Bookmarks': r'bookmarks.*export|favorites.*copy'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for browser_type, pattern in browser_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Browser Data Collection - {browser_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting browser data collection: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_file_collection())
        self.findings.extend(self.hunt_sensitive_data_access())
        self.findings.extend(self.hunt_browser_data_collection())
        
        return {
            'tactic': 'Collection',
            'technique': 'Data from Local System',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = DataLocalSystemHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
