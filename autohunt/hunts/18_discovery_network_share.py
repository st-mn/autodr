#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Hunting - Discovery: Network Share Discovery
Detects network share enumeration and reconnaissance
"""

import json
import re
import sys
from datetime import datetime
from typing import Dict, List

class NetworkShareDiscoveryHunter:
    """Hunt for network share discovery activities"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self.findings = []
        self.timestamp = datetime.now().isoformat()
    
    def hunt_smb_enumeration(self) -> List[Dict]:
        """Detect SMB share enumeration"""
        findings = []
        
        smb_patterns = {
            'Net Share': r'net\s+share|net\s+view|net\s+use',
            'SMB Scan': r'smb.*scan|smbclient|smbmap',
            'Nmap SMB': r'nmap.*smb|nmap.*445',
            'Enum4Linux': r'enum4linux|crackmapexec'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for smb_type, pattern in smb_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'SMB Enumeration - {smb_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting SMB enumeration: {e}")
        
        return findings
    
    def hunt_nfs_discovery(self) -> List[Dict]:
        """Detect NFS share discovery"""
        findings = []
        
        nfs_patterns = {
            'Showmount': r'showmount|nfs.*mount',
            'NFS Scan': r'nfs.*scan|nmap.*nfs',
            'Mount Attempts': r'mount.*nfs|mount.*-t\s+nfs',
            'NFS Enumeration': r'rpcinfo|nfsstat'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for nfs_type, pattern in nfs_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'NFS Discovery - {nfs_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting NFS discovery: {e}")
        
        return findings
    
    def hunt_file_share_access(self) -> List[Dict]:
        """Detect file share access attempts"""
        findings = []
        
        access_patterns = {
            'UNC Path': r'\\\\.*\\.*|/mnt/.*share',
            'Share Mount': r'mount.*share|attach.*share',
            'Access Denied': r'access.*denied|permission.*denied',
            'Share Listing': r'dir.*\\\\|ls.*share'
        }
        
        try:
            if self.log_file:
                with open(self.log_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        for access_type, pattern in access_patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    'type': f'File Share Access - {access_type}',
                                    'line_number': line_num,
                                    'severity': 'MEDIUM',
                                    'timestamp': self.timestamp
                                })
        except Exception as e:
            print(f"Error hunting file share access: {e}")
        
        return findings
    
    def generate_report(self) -> Dict:
        """Generate comprehensive threat hunting report"""
        self.findings.extend(self.hunt_smb_enumeration())
        self.findings.extend(self.hunt_nfs_discovery())
        self.findings.extend(self.hunt_file_share_access())
        
        return {
            'tactic': 'Discovery',
            'technique': 'Network Share Discovery',
            'timestamp': self.timestamp,
            'total_findings': len(self.findings),
            'findings': self.findings
        }

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = None
    
    hunter = NetworkShareDiscoveryHunter(log_file)
    report = hunter.generate_report()
    
    print(json.dumps(report, indent=2))
    return report

if __name__ == '__main__':
    main()
