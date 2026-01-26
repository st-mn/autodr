#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Impact: Defacement
Detects website and system defacement activities
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class DefacementHunter:
    """Hunt for defacement activities"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_web_defacement(self) -> List[Dict]:
        """Detect web defacement"""
        findings = []
        
        web_patterns = {
            'Web Root Access': r'webroot.*modify|modify.*webroot|/var/www',
            'HTML Modification': r'\.html.*modify|modify.*\.html',
            'Web Shell': r'webshell|shell\.php|shell\.asp',
            'Index Replacement': r'index.*replace|replace.*index'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for web_type, pattern in web_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Web Defacement - {web_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting web defacement: {e}")
        
        return findings
    
    def hunt_system_message_modification(self) -> List[Dict]:
        """Detect system message modification"""
        findings = []
        
        message_patterns = {
            'Banner Modification': r'banner.*modify|modify.*banner|motd',
            'Login Screen': r'login.*screen|screen.*modify',
            'Desktop Background': r'background.*change|wallpaper.*change',
            'System Message': r'message.*modify|modify.*message'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for msg_type, pattern in message_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'System Message Modification - {msg_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting system message modification: {e}")
        
        return findings
    
    def hunt_content_replacement(self) -> List[Dict]:
        """Detect content replacement"""
        findings = []
        
        content_patterns = {
            'File Replacement': r'replace.*file|file.*replace',
            'Database Modification': r'database.*modify|modify.*database',
            'API Response': r'api.*response.*modify|modify.*response',
            'Cache Poisoning': r'cache.*poison|poison.*cache'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for content_type, pattern in content_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Content Replacement - {content_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting content replacement: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_web_defacement())
        self.findings.extend(self.hunt_system_message_modification())
        self.findings.extend(self.hunt_content_replacement())
        
        return {
            'tactic': 'Impact',
            'technique': 'Defacement',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = DefacementHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
