#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Reconnaissance: Active Scanning
Detects network scanning activities and port enumeration attempts
"""

import socket
import subprocess
import json
import sys
from datetime import datetime
from typing import Dict, List, Tuple
import re

class ActiveScanningHunter:
    """Hunt for Active Scanning reconnaissance activities"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_nmap_signatures(self) -> List[Dict]:
        """Detect Nmap scanning signatures in network traffic"""
        findings = []
        
        try:
            # Check for Nmap user agent strings in web logs
            nmap_signatures = [
                r'Nmap Scripting Engine',
                r'nmap',
                r'Nmap NSE',
                r'Mozilla/5.0 \(compatible; Nmap Scripting Engine'
            ]
            
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for sig in nmap_signatures:
                            if re.search(sig, line, re.IGNORECASE):
                                findings.append({
                                    'type': 'Nmap Signature Detected',
                                    'line_number': line_num,
                                    'signature': sig,
                                    'log_entry': line.strip()[:100],
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting Nmap signatures: {e}")
        
        return findings
    
    def hunt_port_scanning_patterns(self) -> List[Dict]:
        """Detect port scanning patterns in firewall logs"""
        findings = []
        
        try:
            # Simulate detection of sequential port connection attempts
            port_scan_pattern = r'(\d+\.\d+\.\d+\.\d+).*(?:CONN_ATTEMPT|SYN_SCAN|PORT_SCAN)'
            
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        if re.search(port_scan_pattern, line, re.IGNORECASE):
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if ip_match:
                                findings.append({
                                    'type': 'Port Scanning Pattern',
                                    'source_ip': ip_match.group(1),
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting port scanning patterns: {e}")
        
        return findings
    
    def hunt_vulnerability_scanners(self) -> List[Dict]:
        """Detect vulnerability scanner signatures"""
        findings = []
        
        scanner_signatures = {
            'Nessus': [r'nessus', r'User-Agent.*Nessus'],
            'OpenVAS': [r'openvas', r'User-Agent.*OpenVAS'],
            'Qualys': [r'qualys', r'User-Agent.*Qualys'],
            'Rapid7': [r'rapid7', r'User-Agent.*Rapid7'],
            'Acunetix': [r'acunetix', r'User-Agent.*Acunetix']
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for scanner, patterns in scanner_signatures.items():
                            for pattern in patterns:
                                if re.search(pattern, line, re.IGNORECASE):
                                    findings.append({
                                        'type': 'Vulnerability Scanner Detected',
                                        'scanner': scanner,
                                        'line_number': line_num,
                                        'severity': 'MEDIUM',
                                        'timestamp': self.timestamp
                                    })
        except Exception as e:
            print(f"Error hunting vulnerability scanners: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_nmap_signatures())
        self.findings.extend(self.hunt_port_scanning_patterns())
        self.findings.extend(self.hunt_vulnerability_scanners())
        
        return {
            'tactic': 'Reconnaissance',
            'technique': 'Active Scanning',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = ActiveScanningHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
