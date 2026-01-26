#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Command and Control: Encrypted Channel
Detects encrypted C2 communication channels
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class EncryptedChannelHunter:
    """Hunt for encrypted C2 communication channels"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_tls_ssl_anomalies(self) -> List[Dict]:
        """Detect TLS/SSL anomalies in C2"""
        findings = []
        
        tls_patterns = {
            'Self-Signed Cert': r'self.*signed|untrusted.*certificate',
            'Weak Cipher': r'rc4|md5|des|weak.*cipher',
            'Certificate Pinning': r'certificate.*pin|pin.*bypass',
            'TLS Downgrade': r'sslv3|tls.*downgrade|protocol.*downgrade'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for tls_type, pattern in tls_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'TLS/SSL Anomaly - {tls_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting TLS/SSL anomalies: {e}")
        
        return findings
    
    def hunt_vpn_tunnel_abuse(self) -> List[Dict]:
        """Detect VPN tunnel abuse for C2"""
        findings = []
        
        vpn_patterns = {
            'VPN Connection': r'vpn.*connect|openvpn|wireguard',
            'Tunnel Establishment': r'tunnel.*establish|establish.*tunnel',
            'Suspicious VPN': r'vpn.*unusual|vpn.*suspicious',
            'VPN Traffic': r'vpn.*traffic.*anomaly|anomaly.*vpn'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for vpn_type, pattern in vpn_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'VPN Tunnel Abuse - {vpn_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting VPN tunnel abuse: {e}")
        
        return findings
    
    def hunt_proxy_c2(self) -> List[Dict]:
        """Detect proxy-based C2 communication"""
        findings = []
        
        proxy_patterns = {
            'Proxy Usage': r'proxy.*server|via.*proxy|proxy.*connect',
            'SOCKS Proxy': r'socks4|socks5|socks.*proxy',
            'HTTP Proxy': r'http.*proxy|proxy.*http',
            'Proxy Chain': r'proxy.*chain|chain.*proxy'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for proxy_type, pattern in proxy_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Proxy C2 - {proxy_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting proxy C2: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_tls_ssl_anomalies())
        self.findings.extend(self.hunt_vpn_tunnel_abuse())
        self.findings.extend(self.hunt_proxy_c2())
        
        return {
            'tactic': 'Command and Control',
            'technique': 'Encrypted Channel',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = EncryptedChannelHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
