#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Defense Evasion: Impair Defenses
Detects attempts to disable or impair security defenses
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class ImpairDefensesHunter:
    """Hunt for defense impairment activities"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_antivirus_disabling(self) -> List[Dict]:
        """Detect antivirus disabling attempts"""
        findings = []
        
        av_patterns = {
            'Defender Disable': r'Set-MpPreference.*DisableRealtimeMonitoring|defender.*disable',
            'AV Service Stop': r'stop.*antivirus|antivirus.*stop|windefend.*stop',
            'Registry Modification': r'HKLM.*Defender|DisableAntiSpyware',
            'AV Uninstall': r'uninstall.*antivirus|antivirus.*uninstall'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for av_type, pattern in av_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Antivirus Disabling - {av_type}',
                                    'line_number': line_num,
                                    'severity': 'CRITICAL',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting antivirus disabling: {e}")
        
        return findings
    
    def hunt_firewall_disabling(self) -> List[Dict]:
        """Detect firewall disabling attempts"""
        findings = []
        
        firewall_patterns = {
            'Windows Firewall': r'netsh.*firewall.*off|firewall.*disable',
            'UFW Disable': r'ufw.*disable|disable.*ufw',
            'IPTables': r'iptables.*flush|flush.*rules',
            'Firewall Service': r'stop.*firewall|firewall.*stop'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for fw_type, pattern in firewall_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Firewall Disabling - {fw_type}',
                                    'line_number': line_num,
                                    'severity': 'CRITICAL',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting firewall disabling: {e}")
        
        return findings
    
    def hunt_logging_disabling(self) -> List[Dict]:
        """Detect logging disabling attempts"""
        findings = []
        
        logging_patterns = {
            'Event Log Disable': r'disable.*event.*log|event.*log.*disable',
            'Syslog Disable': r'disable.*syslog|syslog.*disable',
            'Audit Disable': r'auditpol.*disable|disable.*audit',
            'Log Clearing': r'clear.*log|log.*clear|wevtutil.*cl'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for log_type, pattern in logging_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Logging Disabling - {log_type}',
                                    'line_number': line_num,
                                    'severity': 'CRITICAL',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting logging disabling: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_antivirus_disabling())
        self.findings.extend(self.hunt_firewall_disabling())
        self.findings.extend(self.hunt_logging_disabling())
        
        return {
            'tactic': 'Defense Evasion',
            'technique': 'Impair Defenses',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = ImpairDefensesHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
