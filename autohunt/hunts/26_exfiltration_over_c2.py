#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Exfiltration: Exfiltration Over C2 Channel
Detects data exfiltration over C2 channels
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class ExfiltrationC2Hunter:
    """Hunt for data exfiltration over C2 channels"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_large_data_transfers(self) -> List[Dict]:
        """Detect large data transfers over C2"""
        findings = []
        
        transfer_patterns = {
            'Large Upload': r'upload.*large|large.*upload|size.*[0-9]{7,}',
            'Continuous Transfer': r'transfer.*continuous|ongoing.*transfer',
            'Bulk Data': r'bulk.*data|data.*bulk',
            'Suspicious Volume': r'volume.*unusual|unusual.*volume'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for transfer_type, pattern in transfer_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Large Data Transfer - {transfer_type}',
                                    'line_number': line_num,
                                    'severity': 'CRITICAL',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting large data transfers: {e}")
        
        return findings
    
    def hunt_encoded_exfiltration(self) -> List[Dict]:
        """Detect encoded data exfiltration"""
        findings = []
        
        encoding_patterns = {
            'Base64 Encoding': r'base64.*exfil|exfil.*base64',
            'Hex Encoding': r'hex.*encod|encod.*hex',
            'Compression': r'compress.*data|data.*compress',
            'Encryption': r'encrypt.*exfil|exfil.*encrypt'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for encoding_type, pattern in encoding_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Encoded Exfiltration - {encoding_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting encoded exfiltration: {e}")
        
        return findings
    
    def hunt_c2_exfil_indicators(self) -> List[Dict]:
        """Detect C2 exfiltration indicators"""
        findings = []
        
        c2_patterns = {
            'Beacon Response': r'beacon.*response|response.*data',
            'Command Execution': r'command.*execute|execute.*command',
            'Data Staging': r'data.*stage|stage.*data',
            'Callback Pattern': r'callback.*pattern|pattern.*callback'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for c2_type, pattern in c2_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'C2 Exfiltration Indicator - {c2_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting C2 exfiltration indicators: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_large_data_transfers())
        self.findings.extend(self.hunt_encoded_exfiltration())
        self.findings.extend(self.hunt_c2_exfil_indicators())
        
        return {
            'tactic': 'Exfiltration',
            'technique': 'Exfiltration Over C2 Channel',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = ExfiltrationC2Hunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
