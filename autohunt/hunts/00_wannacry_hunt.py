#!/usr/bin/env python3
"""
WannaCry Ransomware Threat Hunt
Detects indicators of WannaCry ransomware activity across endpoints

Detection Vectors:
- Characteristic file names and extensions (.WNCRY, .WNCRYT)
- Known WannaCry process names (tasksche.exe, @WanaDecryptor@.exe)
- SMB/445 exploitation patterns (EternalBlue)
- Registry persistence mechanisms
- Ransom note files (@Please_Read_Me@.txt, @WanaDecryptor@.exe)
- Known file hashes and mutex names
- Network lateral movement via SMB
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from data.data_loader import load_security_data
from typing import Dict, List, Any
import re
from datetime import datetime, timedelta


class WannaCryHunt:
    """Hunt for WannaCry ransomware indicators"""
    
    # Known WannaCry file indicators
    WANNACRY_FILES = [
        'tasksche.exe',
        '@WanaDecryptor@.exe',
        '@WanaDecryptor@.bmp',
        '@Please_Read_Me@.txt',
        '00000000.eky',
        '00000000.pky',
        '00000000.res',
        'c.wnry',
        'f.wnry',
        'm.wnry',
        'msg',
        'r.wnry',
        's.wnry',
        't.wnry',
        'u.wnry',
        'TaskData\\Tor\\taskhsvc.exe'
    ]
    
    # WannaCry encrypted file extensions
    ENCRYPTED_EXTENSIONS = [
        '.WNCRY',
        '.WNCRYT',
        '.WCRY'
    ]
    
    # Known WannaCry SHA256 hashes
    KNOWN_HASHES = [
        'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa',  # Original dropper
        '09a46b3e1be080745a6d8d88d6b5bd351b1c7586ae0dc94d0c238ee36421cafa',  # Dropper variant
        'b9c5d4339809e0ad9a00d4d3dd26fdf44a32819a54abf846bb9b560d81391c25',  # Encryption component
        '24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c',  # Launcher
        'f8812f1deb8001f3b7672b6fc85640ecb123bc2304b563728e6235ccbe782d85'   # Service component
    ]
    
    # Registry keys used by WannaCry
    REGISTRY_INDICATORS = [
        r'HKLM\\SOFTWARE\\WanaCrypt0r',
        r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*tasksche',
        r'HKCU\\SOFTWARE\\WanaCrypt0r'
    ]
    
    # Mutex names
    MUTEX_NAMES = [
        'MsWinZonesCacheCounterMutexA',
        'Global\\MsWinZonesCacheCounterMutexA'
    ]
    
    # SMB/EternalBlue exploitation patterns
    ETERNALBLUE_INDICATORS = {
        'smb_ports': [445, 139],
        'protocols': ['SMBv1', 'SMB1'],
        'exploit_signatures': [
            'MS17-010',
            'EternalBlue',
            'DoublePulsar'
        ]
    }
    
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self.risk_score = 0.0
        self.compromised_hosts = set()
    
    def hunt(self) -> Dict[str, Any]:
        """
        Main hunting routine for WannaCry indicators
        
        Returns:
            Dict containing hunt findings, risk scores, and affected hosts
        """
        print("[*] Starting WannaCry ransomware threat hunt...")
        
        # Load security data from all sources
        data = load_security_data(days=7)  # Look back 7 days
        
        if not data:
            print("[-] No security data available for hunting")
            return self._generate_report()
        
        print(f"[+] Loaded {len(data)} security events for analysis")
        
        # Execute detection routines
        self._detect_wannacry_files(data)
        self._detect_encrypted_files(data)
        self._detect_malicious_processes(data)
        self._detect_registry_persistence(data)
        self._detect_smb_exploitation(data)
        self._detect_network_lateral_movement(data)
        self._detect_file_hashes(data)
        self._detect_mutex_creation(data)
        self._detect_ransom_notes(data)
        
        # Calculate overall risk
        self._calculate_risk_score()
        
        return self._generate_report()
    
    def _detect_wannacry_files(self, data: List[Dict]) -> None:
        """Detect presence of known WannaCry files"""
        print("[*] Hunting for WannaCry file artifacts...")
        
        for event in data:
            file_path = event.get('file_path', '') or event.get('target_filename', '')
            file_name = event.get('file_name', '') or event.get('filename', '')
            
            if not file_path and not file_name:
                continue
            
            full_path = file_path.lower()
            name = file_name.lower()
            
            for indicator in self.WANNACRY_FILES:
                if indicator.lower() in full_path or indicator.lower() in name:
                    self.findings.append({
                        'category': 'WannaCry File Detected',
                        'severity': 'CRITICAL',
                        'confidence': 0.95,
                        'host': event.get('host', event.get('hostname', 'unknown')),
                        'file': file_path or file_name,
                        'indicator': indicator,
                        'timestamp': event.get('timestamp', datetime.now().isoformat()),
                        'details': f"Known WannaCry file '{indicator}' detected on system"
                    })
                    self.compromised_hosts.add(event.get('host', event.get('hostname', 'unknown')))
                    print(f"[!] CRITICAL: WannaCry file '{indicator}' found on {event.get('host', 'unknown')}")
    
    def _detect_encrypted_files(self, data: List[Dict]) -> None:
        """Detect files with WannaCry encryption extensions"""
        print("[*] Hunting for encrypted file extensions...")
        
        extension_counts = {}
        
        for event in data:
            file_path = event.get('file_path', '') or event.get('target_filename', '')
            
            if not file_path:
                continue
            
            for ext in self.ENCRYPTED_EXTENSIONS:
                if file_path.upper().endswith(ext):
                    host = event.get('host', event.get('hostname', 'unknown'))
                    
                    if host not in extension_counts:
                        extension_counts[host] = {}
                    if ext not in extension_counts[host]:
                        extension_counts[host][ext] = 0
                    extension_counts[host][ext] += 1
        
        # Report hosts with multiple encrypted files (indicates active encryption)
        for host, exts in extension_counts.items():
            total_encrypted = sum(exts.values())
            if total_encrypted >= 5:  # Threshold for active encryption
                self.findings.append({
                    'category': 'Mass File Encryption Detected',
                    'severity': 'CRITICAL',
                    'confidence': 0.90,
                    'host': host,
                    'encrypted_count': total_encrypted,
                    'extensions': list(exts.keys()),
                    'timestamp': datetime.now().isoformat(),
                    'details': f"Detected {total_encrypted} files with WannaCry encryption extensions on {host}"
                })
                self.compromised_hosts.add(host)
                print(f"[!] CRITICAL: {total_encrypted} encrypted files detected on {host}")
    
    def _detect_malicious_processes(self, data: List[Dict]) -> None:
        """Detect WannaCry process execution"""
        print("[*] Hunting for malicious process execution...")
        
        for event in data:
            process_name = event.get('process_name', '') or event.get('image', '')
            command_line = event.get('command_line', '') or event.get('cmdline', '')
            
            if not process_name:
                continue
            
            process_lower = process_name.lower()
            
            # Check for known WannaCry processes
            if 'tasksche.exe' in process_lower:
                self.findings.append({
                    'category': 'WannaCry Process Execution',
                    'severity': 'CRITICAL',
                    'confidence': 0.98,
                    'host': event.get('host', event.get('hostname', 'unknown')),
                    'process': process_name,
                    'command_line': command_line,
                    'timestamp': event.get('timestamp', datetime.now().isoformat()),
                    'details': 'WannaCry dropper process (tasksche.exe) detected'
                })
                self.compromised_hosts.add(event.get('host', event.get('hostname', 'unknown')))
                print(f"[!] CRITICAL: tasksche.exe process detected on {event.get('host', 'unknown')}")
            
            elif '@wanadecryptor@' in process_lower or 'wanadecrypt' in process_lower:
                self.findings.append({
                    'category': 'WannaCry Decryptor Process',
                    'severity': 'CRITICAL',
                    'confidence': 0.98,
                    'host': event.get('host', event.get('hostname', 'unknown')),
                    'process': process_name,
                    'command_line': command_line,
                    'timestamp': event.get('timestamp', datetime.now().isoformat()),
                    'details': 'WannaCry decryptor/ransom interface detected'
                })
                self.compromised_hosts.add(event.get('host', event.get('hostname', 'unknown')))
                print(f"[!] CRITICAL: WannaCry decryptor process detected on {event.get('host', 'unknown')}")
    
    def _detect_registry_persistence(self, data: List[Dict]) -> None:
        """Detect WannaCry registry persistence mechanisms"""
        print("[*] Hunting for registry persistence...")
        
        for event in data:
            registry_key = event.get('registry_key', '') or event.get('target_object', '')
            
            if not registry_key:
                continue
            
            for indicator in self.REGISTRY_INDICATORS:
                if re.search(indicator, registry_key, re.IGNORECASE):
                    self.findings.append({
                        'category': 'WannaCry Registry Persistence',
                        'severity': 'HIGH',
                        'confidence': 0.85,
                        'host': event.get('host', event.get('hostname', 'unknown')),
                        'registry_key': registry_key,
                        'indicator_pattern': indicator,
                        'timestamp': event.get('timestamp', datetime.now().isoformat()),
                        'details': f"WannaCry-associated registry key detected: {registry_key}"
                    })
                    self.compromised_hosts.add(event.get('host', event.get('hostname', 'unknown')))
                    print(f"[!] HIGH: WannaCry registry key found on {event.get('host', 'unknown')}")
    
    def _detect_smb_exploitation(self, data: List[Dict]) -> None:
        """Detect SMB/EternalBlue exploitation attempts"""
        print("[*] Hunting for SMB exploitation patterns...")
        
        smb_activity = {}
        
        for event in data:
            dest_port = event.get('dest_port', 0) or event.get('destination_port', 0)
            protocol = event.get('protocol', '').lower()
            event_type = event.get('event_type', '').lower()
            
            # Look for SMB traffic on port 445
            if dest_port == 445 or 'smb' in protocol or 'ms17-010' in str(event).lower():
                src_ip = event.get('src_ip', event.get('source_ip', 'unknown'))
                dest_ip = event.get('dest_ip', event.get('destination_ip', 'unknown'))
                
                if src_ip not in smb_activity:
                    smb_activity[src_ip] = {'targets': set(), 'events': 0}
                
                smb_activity[src_ip]['targets'].add(dest_ip)
                smb_activity[src_ip]['events'] += 1
        
        # Identify scanning behavior (multiple targets from single source)
        for src_ip, activity in smb_activity.items():
            if len(activity['targets']) >= 5 or activity['events'] >= 20:
                self.findings.append({
                    'category': 'SMB Exploitation/Scanning Detected',
                    'severity': 'HIGH',
                    'confidence': 0.80,
                    'source_ip': src_ip,
                    'target_count': len(activity['targets']),
                    'event_count': activity['events'],
                    'targets': list(activity['targets'])[:10],  # Limit to first 10
                    'timestamp': datetime.now().isoformat(),
                    'details': f"Potential EternalBlue/WannaCry propagation detected from {src_ip}"
                })
                print(f"[!] HIGH: SMB exploitation pattern detected from {src_ip} ({len(activity['targets'])} targets)")
    
    def _detect_network_lateral_movement(self, data: List[Dict]) -> None:
        """Detect lateral movement via SMB"""
        print("[*] Hunting for lateral movement patterns...")
        
        # Track internal network SMB connections
        internal_smb = {}
        
        for event in data:
            dest_port = event.get('dest_port', 0) or event.get('destination_port', 0)
            src_ip = event.get('src_ip', event.get('source_ip', ''))
            dest_ip = event.get('dest_ip', event.get('destination_ip', ''))
            
            if dest_port == 445 and src_ip and dest_ip:
                # Check if internal network (simple check for RFC1918)
                if self._is_internal_ip(src_ip) and self._is_internal_ip(dest_ip):
                    if src_ip not in internal_smb:
                        internal_smb[src_ip] = {'count': 0, 'targets': set()}
                    internal_smb[src_ip]['count'] += 1
                    internal_smb[src_ip]['targets'].add(dest_ip)
        
        # Report suspicious lateral movement
        for src_ip, data in internal_smb.items():
            if len(data['targets']) >= 10:  # Touching many internal hosts
                self.findings.append({
                    'category': 'Lateral Movement via SMB',
                    'severity': 'HIGH',
                    'confidence': 0.75,
                    'source_ip': src_ip,
                    'lateral_targets': len(data['targets']),
                    'connection_count': data['count'],
                    'timestamp': datetime.now().isoformat(),
                    'details': f"Suspected WannaCry lateral movement from {src_ip} to {len(data['targets'])} internal hosts"
                })
                print(f"[!] HIGH: Lateral movement detected from {src_ip} to {len(data['targets'])} hosts")
    
    def _detect_file_hashes(self, data: List[Dict]) -> None:
        """Detect known WannaCry file hashes"""
        print("[*] Hunting for known WannaCry file hashes...")
        
        for event in data:
            file_hash = (event.get('hash', '') or 
                        event.get('sha256', '') or 
                        event.get('md5', '')).lower()
            
            if file_hash in [h.lower() for h in self.KNOWN_HASHES]:
                self.findings.append({
                    'category': 'Known WannaCry Hash Detected',
                    'severity': 'CRITICAL',
                    'confidence': 1.0,
                    'host': event.get('host', event.get('hostname', 'unknown')),
                    'file_hash': file_hash,
                    'file_path': event.get('file_path', event.get('target_filename', 'unknown')),
                    'timestamp': event.get('timestamp', datetime.now().isoformat()),
                    'details': 'Known WannaCry malware hash detected'
                })
                self.compromised_hosts.add(event.get('host', event.get('hostname', 'unknown')))
                print(f"[!] CRITICAL: Known WannaCry hash detected on {event.get('host', 'unknown')}")
    
    def _detect_mutex_creation(self, data: List[Dict]) -> None:
        """Detect WannaCry mutex creation"""
        print("[*] Hunting for mutex indicators...")
        
        for event in data:
            mutex_name = event.get('mutex', '') or event.get('object_name', '')
            
            if not mutex_name:
                continue
            
            for known_mutex in self.MUTEX_NAMES:
                if known_mutex.lower() in mutex_name.lower():
                    self.findings.append({
                        'category': 'WannaCry Mutex Detected',
                        'severity': 'HIGH',
                        'confidence': 0.90,
                        'host': event.get('host', event.get('hostname', 'unknown')),
                        'mutex': mutex_name,
                        'timestamp': event.get('timestamp', datetime.now().isoformat()),
                        'details': f"WannaCry mutex '{known_mutex}' detected"
                    })
                    self.compromised_hosts.add(event.get('host', event.get('hostname', 'unknown')))
                    print(f"[!] HIGH: WannaCry mutex detected on {event.get('host', 'unknown')}")
    
    def _detect_ransom_notes(self, data: List[Dict]) -> None:
        """Detect ransom note file creation"""
        print("[*] Hunting for ransom note files...")
        
        ransom_note_patterns = [
            '@please_read_me@',
            '@wanadecryptor@',
            'decrypt_instruction',
            '.txt.wncry'
        ]
        
        for event in data:
            file_path = (event.get('file_path', '') or 
                        event.get('target_filename', '')).lower()
            
            for pattern in ransom_note_patterns:
                if pattern in file_path:
                    self.findings.append({
                        'category': 'Ransom Note Detected',
                        'severity': 'CRITICAL',
                        'confidence': 0.95,
                        'host': event.get('host', event.get('hostname', 'unknown')),
                        'file': file_path,
                        'timestamp': event.get('timestamp', datetime.now().isoformat()),
                        'details': 'WannaCry ransom note file detected'
                    })
                    self.compromised_hosts.add(event.get('host', event.get('hostname', 'unknown')))
                    print(f"[!] CRITICAL: Ransom note detected on {event.get('host', 'unknown')}")
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is in RFC1918 private range"""
        if not ip:
            return False
        
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            first = int(parts[0])
            second = int(parts[1])
            
            # 10.0.0.0/8
            if first == 10:
                return True
            # 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True
            # 192.168.0.0/16
            if first == 192 and second == 168:
                return True
            
            return False
        except:
            return False
    
    def _calculate_risk_score(self) -> None:
        """Calculate overall risk score based on findings"""
        if not self.findings:
            self.risk_score = 0.0
            return
        
        # Weight findings by severity and confidence
        severity_weights = {
            'CRITICAL': 1.0,
            'HIGH': 0.7,
            'MEDIUM': 0.4,
            'LOW': 0.2
        }
        
        total_score = 0.0
        for finding in self.findings:
            severity = finding.get('severity', 'LOW')
            confidence = finding.get('confidence', 0.5)
            weight = severity_weights.get(severity, 0.2)
            total_score += weight * confidence
        
        # Normalize to 0-1 scale
        self.risk_score = min(1.0, total_score / 10.0)
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate final hunt report"""
        return {
            'hunt_name': 'WannaCry Ransomware Hunt',
            'timestamp': datetime.now().isoformat(),
            'risk_score': round(self.risk_score, 3),
            'findings_count': len(self.findings),
            'compromised_hosts': list(self.compromised_hosts),
            'compromised_count': len(self.compromised_hosts),
            'findings': self.findings,
            'recommendations': self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate remediation recommendations"""
        recommendations = []
        
        if self.compromised_hosts:
            recommendations.extend([
                "IMMEDIATE: Isolate all compromised hosts from the network",
                "IMMEDIATE: Disable SMB v1 on all systems",
                "IMMEDIATE: Apply MS17-010 security patch to all Windows systems",
                "HIGH: Conduct forensic analysis on compromised systems",
                "HIGH: Restore affected files from clean backups (do not pay ransom)",
                "HIGH: Reset credentials for all accounts on compromised systems",
                "MEDIUM: Review and update backup procedures",
                "MEDIUM: Implement network segmentation to prevent lateral movement",
                "MEDIUM: Deploy EDR solutions for real-time threat detection"
            ])
        else:
            recommendations.extend([
                "Apply MS17-010 patch if not already deployed",
                "Disable SMB v1 protocol organization-wide",
                "Implement regular security patching schedule",
                "Conduct security awareness training on ransomware",
                "Maintain offline, immutable backups"
            ])
        
        return recommendations


def main():
    """Execute WannaCry threat hunt"""
    hunt = WannaCryHunt()
    results = hunt.hunt()
    
    # Print summary
    print("\n" + "="*70)
    print("WannaCry Ransomware Hunt - Results Summary")
    print("="*70)
    print(f"Risk Score: {results['risk_score']:.2%}")
    print(f"Total Findings: {results['findings_count']}")
    print(f"Compromised Hosts: {results['compromised_count']}")
    
    if results['compromised_hosts']:
        print(f"\nAffected Systems:")
        for host in results['compromised_hosts']:
            print(f"  - {host}")
    
    if results['findings']:
        print(f"\nFindings by Category:")
        categories = {}
        for finding in results['findings']:
            cat = finding['category']
            if cat not in categories:
                categories[cat] = 0
            categories[cat] += 1
        
        for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {cat}: {count}")
    
    print(f"\nRecommendations:")
    for i, rec in enumerate(results['recommendations'], 1):
        print(f"  {i}. {rec}")
    
    print("="*70)
    
    return results


if __name__ == '__main__':
    main()
