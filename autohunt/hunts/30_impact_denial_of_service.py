#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Impact: Denial of Service
Detects denial of service attacks and resource exhaustion
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class DenialOfServiceHunter:
    """Hunt for denial of service attacks"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_network_dos(self) -> List[Dict]:
        """Detect network-based DoS attacks"""
        findings = []
        
        dos_patterns = {
            'Flood Attack': r'flood|ddos|dos.*attack',
            'SYN Flood': r'syn.*flood|syn.*attack',
            'UDP Flood': r'udp.*flood|udp.*attack',
            'ICMP Flood': r'icmp.*flood|ping.*flood'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for dos_type, pattern in dos_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Network DoS - {dos_type}',
                                    'line_number': line_num,
                                    'severity': 'CRITICAL',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting network DoS: {e}")
        
        return findings
    
    def hunt_application_dos(self) -> List[Dict]:
        """Detect application-level DoS attacks"""
        findings = []
        
        app_patterns = {
            'HTTP Flood': r'http.*flood|get.*flood|post.*flood',
            'Slowloris': r'slowloris|slow.*request',
            'Resource Exhaustion': r'resource.*exhaust|exhaust.*resource',
            'CPU Spike': r'cpu.*spike|cpu.*usage.*high'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for app_type, pattern in app_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Application DoS - {app_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting application DoS: {e}")
        
        return findings
    
    def hunt_service_disruption(self) -> List[Dict]:
        """Detect service disruption activities"""
        findings = []
        
        disruption_patterns = {
            'Service Stop': r'service.*stop|stop.*service|systemctl.*stop',
            'Process Kill': r'kill.*process|process.*kill|pkill',
            'Memory Exhaustion': r'memory.*exhaust|exhaust.*memory',
            'Disk Space': r'disk.*full|fill.*disk|disk.*space.*exhaust'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for disruption_type, pattern in disruption_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Service Disruption - {disruption_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting service disruption: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_network_dos())
        self.findings.extend(self.hunt_application_dos())
        self.findings.extend(self.hunt_service_disruption())
        
        return {
            'tactic': 'Impact',
            'technique': 'Denial of Service',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = DenialOfServiceHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
