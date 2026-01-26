#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Exfiltration: Data Transfer Size Limits
Detects data exfiltration with size limits to avoid detection
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class DataSizeLimitsHunter:
    """Hunt for data exfiltration with size limits"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_chunked_transfers(self) -> List[Dict]:
        """Detect chunked data transfers"""
        findings = []
        
        chunked_patterns = {
            'Chunk Size': r'chunk.*size|size.*limit|[0-9]+\s*(?:kb|mb)',
            'Fragmented Transfer': r'fragment|chunk|split.*file',
            'Batch Transfer': r'batch.*transfer|transfer.*batch',
            'Incremental Upload': r'incremental|partial.*upload'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for chunked_type, pattern in chunked_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Chunked Transfer - {chunked_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting chunked transfers: {e}")
        
        return findings
    
    def hunt_throttled_exfiltration(self) -> List[Dict]:
        """Detect throttled/rate-limited exfiltration"""
        findings = []
        
        throttle_patterns = {
            'Rate Limiting': r'rate.*limit|limit.*rate|throttle',
            'Bandwidth Control': r'bandwidth.*limit|limit.*bandwidth',
            'Delay Injection': r'delay.*inject|inject.*delay|sleep',
            'Scheduled Transfer': r'schedule.*transfer|transfer.*schedule'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for throttle_type, pattern in throttle_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Throttled Exfiltration - {throttle_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting throttled exfiltration: {e}")
        
        return findings
    
    def hunt_stealthy_transfers(self) -> List[Dict]:
        """Detect stealthy data transfer patterns"""
        findings = []
        
        stealthy_patterns = {
            'Off-Hours Transfer': r'off.*hours|night.*time|weekend',
            'Mimicking Normal': r'mimic.*normal|normal.*traffic',
            'Slow Exfil': r'slow.*exfil|exfil.*slow',
            'Noise Injection': r'noise.*inject|inject.*noise'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for stealthy_type, pattern in stealthy_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Stealthy Transfer - {stealthy_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting stealthy transfers: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_chunked_transfers())
        self.findings.extend(self.hunt_throttled_exfiltration())
        self.findings.extend(self.hunt_stealthy_transfers())
        
        return {
            'tactic': 'Exfiltration',
            'technique': 'Data Transfer Size Limits',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = DataSizeLimitsHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
