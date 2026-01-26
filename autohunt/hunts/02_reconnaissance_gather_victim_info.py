#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Reconnaissance: Gather Victim Information
Detects OSINT and information gathering activities targeting the organization
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class GatherVictimInfoHunter:
    """Hunt for information gathering reconnaissance activities"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_whois_queries(self) -> List[Dict]:
        """Detect WHOIS lookup queries"""
        findings = []
        
        whois_patterns = [
            r'whois\s+',
            r'WHOIS\s+query',
            r'whois\..*\.com',
            r'port\s+43.*connection'
        ]
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for pattern in whois_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': 'WHOIS Query Detected',
                                    'line_number': line_num,
                                    'pattern': pattern,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting WHOIS queries: {e}")
        
        return findings
    
    def hunt_dns_enumeration(self) -> List[Dict]:
        """Detect DNS enumeration and zone transfer attempts"""
        findings = []
        
        dns_patterns = {
            'Zone Transfer': r'AXFR|zone\s+transfer|dns\s+zone',
            'DNS Brute Force': r'dns.*brute|subdomain.*enum',
            'Reverse DNS': r'reverse\s+dns|PTR\s+query',
            'DNS Wildcard': r'dns.*wildcard|*.domain'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for attack_type, pattern in dns_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'DNS Enumeration - {attack_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting DNS enumeration: {e}")
        
        return findings
    
    def hunt_search_engine_queries(self) -> List[Dict]:
        """Detect search engine reconnaissance queries"""
        findings = []
        
        search_patterns = [
            r'site:.*\.com.*filetype:',
            r'inurl:.*admin',
            r'intext:.*password',
            r'cache:.*\.com',
            r'related:.*\.com'
        ]
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for pattern in search_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': 'Search Engine Reconnaissance',
                                    'line_number': line_num,
                                    'pattern': pattern,
                                    'severity': 'LOW',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting search engine queries: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_whois_queries())
        self.findings.extend(self.hunt_dns_enumeration())
        self.findings.extend(self.hunt_search_engine_queries())
        
        return {
            'tactic': 'Reconnaissance',
            'technique': 'Gather Victim Information',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = GatherVictimInfoHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
