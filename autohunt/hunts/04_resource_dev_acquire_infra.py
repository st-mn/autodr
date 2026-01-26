#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Resource Development: Acquire Infrastructure
Detects acquisition of malicious infrastructure and domain registration activities
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class AcquireInfrastructureHunter:
    """Hunt for infrastructure acquisition activities"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_domain_registration(self) -> List[Dict]:
        """Detect suspicious domain registration patterns"""
        findings = []
        
        suspicious_patterns = {
            'Typosquatting': r'(?:gmai|yahooo|microsft|appl)[a-z0-9]*\.com',
            'Lookalike Domains': r'(?:company|bank|paypal)[-_]?[0-9]+\.com',
            'Suspicious TLDs': r'\.tk|\.ml|\.ga|\.cf|\.pw',
            'Newly Registered': r'whois.*created.*(?:2024|2025)'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for attack_type, pattern in suspicious_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Suspicious Domain - {attack_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting domain registration: {e}")
        
        return findings
    
    def hunt_vps_hosting_acquisition(self) -> List[Dict]:
        """Detect VPS and hosting provider acquisition"""
        findings = []
        
        hosting_providers = [
            'DigitalOcean', 'Linode', 'Vultr', 'AWS', 'Azure', 'GCP',
            'Hetzner', 'OVH', 'NameCheap', 'GoDaddy'
        ]
        
        vps_patterns = [
            r'VPS\s+(?:purchase|order|account)',
            r'(?:' + '|'.join(hosting_providers) + r').*account.*created',
            r'cloud.*instance.*launched',
            r'server.*provisioned'
        ]
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for pattern in vps_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': 'VPS/Hosting Acquisition',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting VPS acquisition: {e}")
        
        return findings
    
    def hunt_botnet_infrastructure(self) -> List[Dict]:
        """Detect botnet and C2 infrastructure indicators"""
        findings = []
        
        botnet_patterns = {
            'C2 Server Setup': r'c2|command.*control|beacon.*server',
            'DGA Domains': r'domain.*generation|dga.*domain',
            'Fast Flux': r'fast.*flux|ip.*rotation',
            'Bulletproof Hosting': r'bulletproof.*host|abuse.*tolerant'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for infra_type, pattern in botnet_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Botnet Infrastructure - {infra_type}',
                                    'line_number': line_num,
                                    'severity': 'CRITICAL',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting botnet infrastructure: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_domain_registration())
        self.findings.extend(self.hunt_vps_hosting_acquisition())
        self.findings.extend(self.hunt_botnet_infrastructure())
        
        return {
            'tactic': 'Resource Development',
            'technique': 'Acquire Infrastructure',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = AcquireInfrastructureHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
