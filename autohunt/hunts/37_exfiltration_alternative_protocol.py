#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Exfiltration: Exfiltration Over Alternative Protocol
Detects data exfiltration using non-standard protocols
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class AlternativeProtocolHunter:
    """Hunt for exfiltration over alternative protocols"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_ftp_exfiltration(self) -> List[Dict]:
        """Detect FTP-based exfiltration"""
        findings = []
        
        ftp_patterns = {
            'FTP Transfer': r'ftp.*upload|upload.*ftp|ftp.*put',
            'SFTP Usage': r'sftp.*put|put.*sftp',
            'FTP Credentials': r'ftp.*user|ftp.*password',
            'FTP Port': r'port.*21|ftp.*port'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for ftp_type, pattern in ftp_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'FTP Exfiltration - {ftp_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting FTP exfiltration: {e}")
        
        return findings
    
    def hunt_dns_exfiltration(self) -> List[Dict]:
        """Detect DNS-based exfiltration"""
        findings = []
        
        dns_patterns = {
            'DNS Tunnel': r'dns.*tunnel|tunnel.*dns|dnscat',
            'Large DNS Query': r'dns.*query.*large|query.*size.*large',
            'Subdomain Exfil': r'subdomain.*exfil|exfil.*subdomain',
            'DNS TXT Record': r'txt.*record|record.*txt'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for dns_type, pattern in dns_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'DNS Exfiltration - {dns_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting DNS exfiltration: {e}")
        
        return findings
    
    def hunt_icmp_exfiltration(self) -> List[Dict]:
        """Detect ICMP-based exfiltration"""
        findings = []
        
        icmp_patterns = {
            'ICMP Tunnel': r'icmp.*tunnel|tunnel.*icmp|ptunnel',
            'Ping Exfil': r'ping.*data|data.*ping',
            'ICMP Echo': r'icmp.*echo|echo.*request',
            'Covert Channel': r'covert.*channel|channel.*covert'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for icmp_type, pattern in icmp_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'ICMP Exfiltration - {icmp_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting ICMP exfiltration: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_ftp_exfiltration())
        self.findings.extend(self.hunt_dns_exfiltration())
        self.findings.extend(self.hunt_icmp_exfiltration())
        
        return {
            'tactic': 'Exfiltration',
            'technique': 'Exfiltration Over Alternative Protocol',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = AlternativeProtocolHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
