#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Discovery: System Information Discovery
Detects system information gathering and reconnaissance
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class SystemInfoDiscoveryHunter:
    """Hunt for system information discovery activities"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_system_enumeration(self) -> List[Dict]:
        """Detect system enumeration commands"""
        findings = []
        
        enum_patterns = {
            'Windows System Info': r'systeminfo|wmic\s+os\s+get|Get-ComputerInfo',
            'Linux System Info': r'uname\s+-a|lsb_release|hostnamectl',
            'Hardware Info': r'lsblk|lspci|dmidecode',
            'Kernel Info': r'uname.*-r|kernel.*version'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for enum_type, pattern in enum_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'System Enumeration - {enum_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting system enumeration: {e}")
        
        return findings
    
    def hunt_security_software_discovery(self) -> List[Dict]:
        """Detect security software discovery"""
        findings = []
        
        security_patterns = {
            'Antivirus Check': r'(?:wmic|Get-WmiObject).*antivirus|Get-MpComputerStatus',
            'Defender Status': r'defender|windows.*defender|get-mppreference',
            'Firewall Check': r'netsh.*firewall|Get-NetFirewallProfile',
            'EDR Detection': r'edr.*check|endpoint.*detection'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for sec_type, pattern in security_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Security Software Discovery - {sec_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting security software discovery: {e}")
        
        return findings
    
    def hunt_network_configuration_discovery(self) -> List[Dict]:
        """Detect network configuration discovery"""
        findings = []
        
        network_patterns = {
            'IP Configuration': r'ipconfig|ifconfig|ip\s+addr',
            'DNS Configuration': r'nslookup|dig|getaddrinfo',
            'Route Table': r'route\s+print|netstat|ip\s+route',
            'Network Adapters': r'Get-NetAdapter|ifconfig.*-a'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for net_type, pattern in network_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Network Configuration Discovery - {net_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting network configuration discovery: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_system_enumeration())
        self.findings.extend(self.hunt_security_software_discovery())
        self.findings.extend(self.hunt_network_configuration_discovery())
        
        return {
            'tactic': 'Discovery',
            'technique': 'System Information Discovery',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = SystemInfoDiscoveryHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
