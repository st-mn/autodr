#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Discovery: Process Discovery
Detects process enumeration and reconnaissance activities
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class ProcessDiscoveryHunter:
    """Hunt for process discovery activities"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_process_enumeration(self) -> List[Dict]:
        """Detect process enumeration commands"""
        findings = []
        
        enum_patterns = {
            'Task List': r'tasklist|get-process|ps\s+aux',
            'Process Details': r'wmic.*process|Get-WmiObject.*process',
            'Service Enumeration': r'tasklist.*svc|sc.*query',
            'Process Tree': r'pstree|process.*tree'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for enum_type, pattern in enum_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Process Enumeration - {enum_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting process enumeration: {e}")
        
        return findings
    
    def hunt_suspicious_process_queries(self) -> List[Dict]:
        """Detect queries for specific suspicious processes"""
        findings = []
        
        suspicious_patterns = {
            'Security Tools': r'(?:tasklist|wmic|get-process).*(?:defender|antivirus|edr|siem)',
            'Monitoring Tools': r'(?:tasklist|wmic).*(?:wireshark|tcpdump|procmon)',
            'Analysis Tools': r'(?:tasklist|wmic).*(?:ida|ghidra|debugger)',
            'Credential Tools': r'(?:tasklist|wmic).*(?:mimikatz|hashcat|john)'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for susp_type, pattern in suspicious_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Suspicious Process Query - {susp_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting suspicious process queries: {e}")
        
        return findings
    
    def hunt_process_monitoring(self) -> List[Dict]:
        """Detect process monitoring and inspection"""
        findings = []
        
        monitoring_patterns = {
            'Debugger Attach': r'debugger.*attach|gdb.*attach|lldb.*attach',
            'Strace': r'strace|ltrace|dtrace',
            'Procfs Access': r'/proc/.*cmdline|/proc/.*maps|/proc/.*fd',
            'Memory Inspection': r'memory.*dump|memory.*inspect'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for monitor_type, pattern in monitoring_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Process Monitoring - {monitor_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting process monitoring: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_process_enumeration())
        self.findings.extend(self.hunt_suspicious_process_queries())
        self.findings.extend(self.hunt_process_monitoring())
        
        return {
            'tactic': 'Discovery',
            'technique': 'Process Discovery',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = ProcessDiscoveryHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
