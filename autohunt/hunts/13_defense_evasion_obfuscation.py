#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Defense Evasion: Obfuscated Files or Information
Detects obfuscation and encoding techniques used for evasion
"""

import json
import re
import sys
import base64
from datetime import datetime
from typing import Dict, List

class ObfuscationHunter:
    """Hunt for obfuscation and encoding evasion techniques"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_base64_encoding(self) -> List[Dict]:
        """Detect base64 encoded payloads"""
        findings = []
        
        base64_patterns = {
            'PowerShell Encoding': r'-enc\s+[A-Za-z0-9+/=]{50,}',
            'Base64 Strings': r'[A-Za-z0-9+/]{50,}={0,2}',
            'Encoded Commands': r'base64.*decode|base64.*encode',
            'Suspicious Encoding': r'\\x[0-9a-f]{2}'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for enc_type, pattern in base64_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Base64 Encoding - {enc_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting base64 encoding: {e}")
        
        return findings
    
    def hunt_code_obfuscation(self) -> List[Dict]:
        """Detect code obfuscation techniques"""
        findings = []
        
        obfuscation_patterns = {
            'Variable Obfuscation': r'\$\{.*\}|\$\(.*\)|eval\(.*\)',
            'String Concatenation': r'\".*\"\s*\+\s*\".*\"',
            'Hex Encoding': r'0x[0-9a-f]{2}',
            'ROT13': r'rot13|caesar.*cipher'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for obf_type, pattern in obfuscation_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Code Obfuscation - {obf_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting code obfuscation: {e}")
        
        return findings
    
    def hunt_file_obfuscation(self) -> List[Dict]:
        """Detect file and path obfuscation"""
        findings = []
        
        file_patterns = {
            'Alternative Data Streams': r'::.*\$DATA|ads\s+create',
            'Hidden Files': r'attrib.*\+h|hidden.*file',
            'Null Byte': r'\\x00|null.*byte',
            'Case Manipulation': r'(?:sYsTeM|cMd|pOwErShElL)'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for file_type, pattern in file_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'File Obfuscation - {file_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting file obfuscation: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_base64_encoding())
        self.findings.extend(self.hunt_code_obfuscation())
        self.findings.extend(self.hunt_file_obfuscation())
        
        return {
            'tactic': 'Defense Evasion',
            'technique': 'Obfuscated Files or Information',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = ObfuscationHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
