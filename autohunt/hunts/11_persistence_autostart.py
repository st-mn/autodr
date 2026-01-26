#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Persistence: Boot or Logon Autostart Execution
Detects persistence mechanisms using autostart locations
"""

import json
import re
import sys
import os
from datetime import datetime
from typing import Dict, List

class AutostartPersistenceHunter:
    """Hunt for autostart persistence mechanisms"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_registry_autorun(self) -> List[Dict]:
        """Detect registry autorun modifications"""
        findings = []
        
        registry_patterns = {
            'Run Key': r'HKLM.*\\Run|HKCU.*\\Run',
            'RunOnce': r'\\RunOnce|run.*once',
            'Services': r'HKLM.*\\Services|service.*start',
            'Winlogon': r'Winlogon|userinit'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for reg_type, pattern in registry_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Registry Autorun - {reg_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting registry autorun: {e}")
        
        return findings
    
    def hunt_startup_folders(self) -> List[Dict]:
        """Detect suspicious files in startup folders"""
        findings = []
        
        startup_patterns = {
            'Windows Startup': r'startup.*folder|\\startup|\\appdata.*startup',
            'Linux Init': r'/etc/init\.d|/etc/rc\.|/etc/systemd',
            'LaunchDaemon': r'~/Library/LaunchDaemons|~/Library/LaunchAgents',
            'Cron Jobs': r'crontab.*edit|/etc/cron|@reboot'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for startup_type, pattern in startup_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Startup Folder - {startup_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting startup folders: {e}")
        
        return findings
    
    def hunt_scheduled_tasks(self) -> List[Dict]:
        """Detect suspicious scheduled task creation"""
        findings = []
        
        task_patterns = {
            'Task Scheduler': r'schtasks.*\/create|at\s+\d+:\d+',
            'Cron Execution': r'cron.*create|crontab.*-e',
            'LaunchAgent': r'launchctl.*load|plist.*launch',
            'Systemd Timer': r'systemctl.*enable|timer.*create'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for task_type, pattern in task_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'Scheduled Task - {task_type}',
                                    'line_number': line_num,
                                    'severity': 'HIGH',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting scheduled tasks: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_registry_autorun())
        self.findings.extend(self.hunt_startup_folders())
        self.findings.extend(self.hunt_scheduled_tasks())
        
        return {
            'tactic': 'Persistence',
            'technique': 'Boot or Logon Autostart Execution',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = AutostartPersistenceHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
