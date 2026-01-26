#!/usr/bin/env python3
"""
Scattered Spider macOS Persistence Hunt
Comprehensive threat hunting for identity-first attacks and macOS persistence mechanisms
targeting Scattered Spider (UNC3944/Octo Tempest/Muddled Libra) tactics.

This hunt focuses on:
- RMM tool abuse for persistence
- MFA fatigue and identity pivot detection
- LaunchAgent/LaunchDaemon persistence
- Suspicious help desk activity correlation
- Phishing-resistant bypass attempts
"""

import json
import re
import sys
import os
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from collections import defaultdict
import hashlib

class ScatteredSpiderMacOSHunter:
    """Hunt for Scattered Spider macOS persistence and identity attacks"""
    
    def __init__(self, 
                 crowdstrike_logs: str = None, 
                 splunk_logs: str = None,
                 sso_logs: str = None,
                 osquery_logs: str = None):
        self.crowdstrike_logs = crowdstrike_logs
        self.splunk_logs = splunk_logs
        self.sso_logs = sso_logs
        self.osquery_logs = osquery_logs
        self.findings = []
        self.timestamp = datetime.now().isoformat()
        self.riskScore = 0
        
        # Known Scattered Spider RMM tools and variants
        self.rmm_tools = {
            'AnyDesk': ['anydesk', 'anydesk.app', 'ad_svc', 'anydesk.exe'],
            'ScreenConnect': ['screenconnect', 'connectwisecontrol', 'connectwise', 'screenconnectclient'],
            'TeamViewer': ['teamviewer', 'teamviewer.app', 'tv_w32', 'tv_x64'],
            'Tailscale': ['tailscale', 'tailscaled', 'tailscale.app'],
            'Splashtop': ['splashtop', 'srservice', 'splashtop.app'],
            'Chrome Remote Desktop': ['chrome_remote_desktop', 'remoting_host', 'crd_host'],
            'LogMeIn': ['logmein', 'hamachi', 'logmeingui'],
            'GoToAssist': ['gotoassist', 'g2ax_comm', 'g2aservice'],
            'DWService': ['dwservice', 'dwagent'],
            'RustDesk': ['rustdesk', 'rustdesk.app', 'sciter']
        }
        
        # Tunneling tools often used by Scattered Spider
        self.tunnel_tools = {
            'Ngrok': ['ngrok', 'ngrok.exe', 'ngrok.app'],
            'Cloudflared': ['cloudflared', 'cloudflare-tunnel', 'argo'],
            'Teleport': ['teleport', 'tsh', 'tctl'],
            'Chisel': ['chisel', 'chisel.exe'],
            'Frp': ['frpc', 'frps', 'frp'],
            'SSH Tunnels': ['ssh.*-L', 'ssh.*-R', 'ssh.*-D']
        }
        
        # macOS persistence locations
        self.macos_persistence_paths = [
            "/Library/LaunchAgents/",
            "/Library/LaunchDaemons/", 
            "/System/Library/LaunchAgents/",
            "/System/Library/LaunchDaemons/",
            "~/Library/LaunchAgents/",
            "/etc/periodic/",
            "~/.bashrc",
            "~/.zshrc",
            "~/.profile",
            "/etc/rc.common"
        ]

    def hunt_rmm_persistence(self) -> List[Dict]:
        """Hunt for RMM tool installations and persistence"""
        findings = []
        
        # CrowdStrike process detection
        if self.crowdstrike_logs:
            try:
                with open(self.crowdstrike_logs, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        line_lower = line.lower()
                        
                        # Check for RMM tool execution
                        for tool_name, variants in self.rmm_tools.items():
                            for variant in variants:
                                if variant in line_lower:
                                    # Additional context checks
                                    suspicious_paths = ['/tmp/', '/var/tmp/', '/users/shared/', '/applications/']
                                    is_suspicious_location = any(path in line_lower for path in suspicious_paths)
                                    
                                    severity = "CRITICAL" if is_suspicious_location else "HIGH"
                                    
                                    findings.append({
                                        'hunt_type': 'RMM Tool Detection',
                                        'tool': tool_name,
                                        'variant': variant,
                                        'line_number': line_num,
                                        'severity': severity,
                                        'description': f'Detected {tool_name} execution - common Scattered Spider persistence',
                                        'timestamp': self.timestamp,
                                        'raw_log': line.strip()
                                    })
                                    self.riskScore += 15 if severity == "CRITICAL" else 10
                                    
            except Exception as e:
                print(f"Error hunting RMM tools in CrowdStrike logs: {e}")
        
        return findings

    def hunt_tunneling_tools(self) -> List[Dict]:
        """Hunt for network tunneling tools used for C2"""
        findings = []
        
        if self.crowdstrike_logs:
            try:
                with open(self.crowdstrike_logs, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        line_lower = line.lower()
                        
                        for tool_name, variants in self.tunnel_tools.items():
                            for variant in variants:
                                if variant in line_lower:
                                    # Check for suspicious arguments
                                    suspicious_args = ['tcp:', 'http:', 'https:', '--authtoken', '--region', '--subdomain']
                                    has_tunnel_args = any(arg in line_lower for arg in suspicious_args)
                                    
                                    severity = "CRITICAL" if has_tunnel_args else "HIGH"
                                    
                                    findings.append({
                                        'hunt_type': 'Tunneling Tool Detection',
                                        'tool': tool_name,
                                        'variant': variant,
                                        'line_number': line_num,
                                        'severity': severity,
                                        'description': f'Detected {tool_name} - potential C2 tunnel',
                                        'timestamp': self.timestamp,
                                        'raw_log': line.strip()
                                    })
                                    self.riskScore += 20 if severity == "CRITICAL" else 12
                                    
            except Exception as e:
                print(f"Error hunting tunneling tools: {e}")
        
        return findings

    def hunt_macos_persistence(self) -> List[Dict]:
        """Hunt for macOS-specific persistence mechanisms"""
        findings = []
        
        if self.osquery_logs:
            try:
                with open(self.osquery_logs, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        line_lower = line.lower()
                        
                        # Check for suspicious LaunchAgent/LaunchDaemon creation
                        for persistence_path in self.macos_persistence_paths:
                            if persistence_path.lower() in line_lower:
                                # Look for non-Apple signed binaries
                                is_apple_signed = 'com.apple' in line_lower
                                has_suspicious_name = any(name in line_lower for name in 
                                    ['update', 'service', 'agent', 'daemon', 'helper', 'launcher'])
                                
                                if not is_apple_signed and has_suspicious_name:
                                    findings.append({
                                        'hunt_type': 'macOS Persistence',
                                        'persistence_type': 'LaunchAgent/LaunchDaemon',
                                        'path': persistence_path,
                                        'line_number': line_num,
                                        'severity': 'HIGH',
                                        'description': 'Suspicious non-Apple persistence mechanism',
                                        'timestamp': self.timestamp,
                                        'raw_log': line.strip()
                                    })
                                    self.riskScore += 12
                                    
            except Exception as e:
                print(f"Error hunting macOS persistence: {e}")
        
        return findings

    def hunt_mfa_fatigue_attacks(self) -> List[Dict]:
        """Hunt for MFA fatigue and rapid authentication attempts"""
        findings = []
        mfa_events = defaultdict(list)
        
        if self.sso_logs:
            try:
                with open(self.sso_logs, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        # Parse SSO logs for MFA events
                        if 'mfa' in line.lower() or 'factor' in line.lower():
                            # Extract user and timestamp (simplified parsing)
                            user_match = re.search(r'user["\s]*[:=]["\s]*([^\s,"]+)', line, re.IGNORECASE)
                            time_match = re.search(r'timestamp["\s]*[:=]["\s]*([^\s,"]+)', line, re.IGNORECASE)
                            
                            if user_match and time_match:
                                user = user_match.group(1)
                                timestamp = time_match.group(1)
                                mfa_events[user].append((timestamp, line_num, line.strip()))
                
                # Analyze for MFA fatigue patterns
                for user, events in mfa_events.items():
                    if len(events) >= 5:  # 5+ MFA attempts
                        # Check if events are within short time window
                        recent_events = 0
                        for i in range(len(events) - 1):
                            try:
                                # Simplified time comparison
                                current_time = datetime.fromisoformat(events[i][0].replace('Z', '+00:00'))
                                next_time = datetime.fromisoformat(events[i+1][0].replace('Z', '+00:00'))
                                if (next_time - current_time).total_seconds() < 120:  # 2 minutes
                                    recent_events += 1
                            except:
                                continue
                        
                        if recent_events >= 4:  # 4+ rapid attempts
                            findings.append({
                                'hunt_type': 'MFA Fatigue Attack',
                                'user': user,
                                'attempts_count': len(events),
                                'rapid_attempts': recent_events,
                                'severity': 'CRITICAL',
                                'description': f'User {user} had {len(events)} MFA attempts with {recent_events} rapid succession',
                                'timestamp': self.timestamp
                            })
                            self.riskScore += 25
                            
            except Exception as e:
                print(f"Error hunting MFA fatigue: {e}")
        
        return findings

    def hunt_help_desk_social_engineering(self) -> List[Dict]:
        """Hunt for help desk social engineering indicators"""
        findings = []
        
        if self.sso_logs:
            try:
                help_desk_indicators = []
                device_registrations = []
                password_resets = []
                
                with open(self.sso_logs, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        line_lower = line.lower()
                        
                        # Look for help desk related activities
                        help_desk_keywords = ['password reset', 'device register', 'mfa reset', 
                                            'phone change', 'recovery', 'unlock account']
                        
                        for keyword in help_desk_keywords:
                            if keyword in line_lower:
                                user_match = re.search(r'user["\s]*[:=]["\s]*([^\s,"]+)', line, re.IGNORECASE)
                                if user_match:
                                    user = user_match.group(1)
                                    
                                    if 'password reset' in keyword:
                                        password_resets.append((user, line_num, self.timestamp))
                                    elif 'device register' in keyword or 'mfa' in keyword:
                                        device_registrations.append((user, line_num, self.timestamp))
                
                # Correlate password resets with device registrations
                for reset_user, reset_line, reset_time in password_resets:
                    for reg_user, reg_line, reg_time in device_registrations:
                        if reset_user == reg_user:
                            findings.append({
                                'hunt_type': 'Help Desk Social Engineering',
                                'user': reset_user,
                                'pattern': 'Password Reset + Device Registration',
                                'reset_line': reset_line,
                                'registration_line': reg_line,
                                'severity': 'CRITICAL',
                                'description': f'User {reset_user} had password reset followed by device registration - classic Scattered Spider pattern',
                                'timestamp': self.timestamp
                            })
                            self.riskScore += 30
                            
            except Exception as e:
                print(f"Error hunting help desk social engineering: {e}")
        
        return findings

    def hunt_residential_proxy_logins(self) -> List[Dict]:
        """Hunt for logins from residential proxy networks"""
        findings = []
        
        # Common residential proxy IP ranges and ASNs
        residential_proxy_asns = [
            'AS714',     # Apple (often abused)
            'AS7922',    # Comcast
            'AS20115',   # Charter
            'AS22773',   # Cox
            'AS3209',    # Vodafone
        ]
        
        residential_proxy_keywords = [
            'residential', 'proxy', 'tunnel', 'vpn', 'tor',
            'brightdata', 'luminati', 'oxylabs', 'smartproxy'
        ]
        
        if self.sso_logs:
            try:
                with open(self.sso_logs, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        line_lower = line.lower()
                        
                        # Check for proxy indicators
                        for keyword in residential_proxy_keywords:
                            if keyword in line_lower:
                                user_match = re.search(r'user["\s]*[:=]["\s]*([^\s,"]+)', line, re.IGNORECASE)
                                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                                
                                if user_match and ip_match:
                                    findings.append({
                                        'hunt_type': 'Residential Proxy Login',
                                        'user': user_match.group(1),
                                        'ip': ip_match.group(1),
                                        'indicator': keyword,
                                        'line_number': line_num,
                                        'severity': 'HIGH',
                                        'description': f'Login from potential residential proxy: {keyword}',
                                        'timestamp': self.timestamp,
                                        'raw_log': line.strip()
                                    })
                                    self.riskScore += 15
                                    
            except Exception as e:
                print(f"Error hunting residential proxy logins: {e}")
        
        return findings

    def hunt_saas_data_exfiltration(self) -> List[Dict]:
        """Hunt for SaaS data exfiltration patterns (Salesforce, Snowflake, etc.)"""
        findings = []
        
        # SaaS platforms commonly targeted by Scattered Spider
        saas_platforms = {
            'Salesforce': ['salesforce.com', 'force.com', 'lightning.force.com'],
            'Snowflake': ['snowflakecomputing.com', 'snowflake.com'],
            'AWS': ['amazonaws.com', 'aws.amazon.com'],
            'Azure': ['azure.com', 'microsoft.com', 'office365.com'],
            'Slack': ['slack.com', 'slack-edge.com']
        }
        
        if self.splunk_logs:
            try:
                with open(self.splunk_logs, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        line_lower = line.lower()
                        
                        # Look for large data downloads from SaaS platforms
                        for platform, domains in saas_platforms.items():
                            for domain in domains:
                                if domain in line_lower:
                                    # Check for download/export indicators
                                    download_keywords = ['download', 'export', 'bulk', 'csv', 'json', 'api']
                                    size_indicators = ['gb', 'mb', 'bytes']
                                    
                                    has_download = any(keyword in line_lower for keyword in download_keywords)
                                    has_size = any(indicator in line_lower for indicator in size_indicators)
                                    
                                    if has_download and has_size:
                                        findings.append({
                                            'hunt_type': 'SaaS Data Exfiltration',
                                            'platform': platform,
                                            'domain': domain,
                                            'line_number': line_num,
                                            'severity': 'CRITICAL',
                                            'description': f'Potential bulk data download from {platform}',
                                            'timestamp': self.timestamp,
                                            'raw_log': line.strip()
                                        })
                                        self.riskScore += 25
                                        
            except Exception as e:
                print(f"Error hunting SaaS data exfiltration: {e}")
        
        return findings

    def generate_splunk_queries(self) -> Dict[str, str]:
        """Generate Splunk queries for ongoing monitoring"""
        queries = {
            "mfa_fatigue_detection": '''
index=sso_logs sourcetype="okta" OR sourcetype="azure_ad"
| search eventType="user.mfa.factor.attempt" OR eventType="user.authentication.auth_via_mfa"
| eval user=coalesce(actor.alternateId, user.name, userPrincipalName)
| bucket _time span=2m
| stats count as mfa_attempts by user, _time
| where mfa_attempts >= 5
| sort - mfa_attempts
            ''',
            
            "help_desk_correlation": '''
index=sso_logs 
| search (eventType="user.account.reset_password" OR eventType="user.mfa.factor.activate")
| eval user=coalesce(actor.alternateId, user.name)
| transaction user maxspan=30m
| where eventcount >= 2
| table _time user eventcount
            ''',
            
            "rmm_tool_detection": '''
index=crowdstrike_logs sourcetype="crowdstrike:json"
| search ImageFileName IN ("*anydesk*", "*teamviewer*", "*screenconnect*", "*tailscale*")
| eval rmm_tool=case(
    match(ImageFileName, ".*anydesk.*"), "AnyDesk",
    match(ImageFileName, ".*teamviewer.*"), "TeamViewer", 
    match(ImageFileName, ".*screenconnect.*"), "ScreenConnect",
    match(ImageFileName, ".*tailscale.*"), "Tailscale",
    true(), "Unknown"
)
| stats count by rmm_tool, ComputerName, UserName
            ''',
            
            "macos_persistence_hunt": '''
index=osquery_logs sourcetype="osquery:results" 
| search path="*/Library/LaunchAgents/*" OR path="*/Library/LaunchDaemons/*"
| where NOT match(label, "com.apple.*")
| stats count by label, program, program_arguments, path
            ''',
            
            "residential_proxy_detection": '''
index=sso_logs
| search client.geographicalContext.country!="US" OR client.ipAddress IN (residential_proxy_ranges.csv)
| eval risk_score=if(match(client.userAgent, ".*(residential|proxy|tunnel).*"), 10, 5)
| stats sum(risk_score) as total_risk by actor.alternateId
| where total_risk > 20
            '''
        }
        
        return queries

    def run_all_hunts(self) -> Dict:
        """Execute all hunting functions and return consolidated results"""
        all_findings = []
        
        print("[+] Starting Scattered Spider macOS Persistence Hunt...")
        
        # Run individual hunts
        hunt_results = {
            'rmm_persistence': self.hunt_rmm_persistence(),
            'tunneling_tools': self.hunt_tunneling_tools(),
            'macos_persistence': self.hunt_macos_persistence(),
            'mfa_fatigue': self.hunt_mfa_fatigue_attacks(),
            'help_desk_social_eng': self.hunt_help_desk_social_engineering(),
            'residential_proxy': self.hunt_residential_proxy_logins(),
            'saas_exfiltration': self.hunt_saas_data_exfiltration()
        }
        
        # Consolidate findings
        for hunt_type, findings in hunt_results.items():
            all_findings.extend(findings)
            print(f"[+] {hunt_type}: Found {len(findings)} indicators")
        
        # Calculate threat level
        if self.riskScore >= 100:
            threat_level = "CRITICAL"
        elif self.riskScore >= 50:
            threat_level = "HIGH" 
        elif self.riskScore >= 25:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"
        
        # Generate summary report
        summary = {
            'hunt_name': 'Scattered Spider macOS Persistence Hunt',
            'timestamp': self.timestamp,
            'total_findings': len(all_findings),
            'risk_score': self.riskScore,
            'threat_level': threat_level,
            'findings_by_type': {hunt_type: len(findings) for hunt_type, findings in hunt_results.items()},
            'detailed_findings': all_findings,
            'splunk_queries': self.generate_splunk_queries(),
            'recommendations': self.generate_recommendations()
        }
        
        return summary

    def generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations based on findings"""
        recommendations = [
            "Implement FIDO2/WebAuthn for phishing-resistant MFA",
            "Review and restrict RMM tool installations to approved tools only",
            "Implement help desk callback verification procedures",
            "Monitor for rapid MFA attempts (>5 in 2 minutes)",
            "Block residential proxy networks at perimeter",
            "Implement SaaS data loss prevention (DLP) monitoring",
            "Review LaunchAgent/LaunchDaemon persistence regularly",
            "Correlate SSO logs with endpoint detection data",
            "Implement behavioral analytics for identity abuse",
            "Create alerts for password reset + device registration patterns"
        ]
        
        # Add specific recommendations based on risk score
        if self.riskScore >= 50:
            recommendations.extend([
                "URGENT: Review all recent help desk password reset requests",
                "URGENT: Audit all registered MFA devices for suspicious additions",
                "URGENT: Check for unauthorized RMM tool installations"
            ])
        
        return recommendations


def hunt(crowdstrike_logs=None, splunk_logs=None, sso_logs=None, osquery_logs=None, **kwargs):
    """
    Execute Scattered Spider macOS persistence hunt
    
    Args:
        crowdstrike_logs: Path to CrowdStrike log files
        splunk_logs: Path to Splunk log files
        sso_logs: Path to SSO log files (Okta/Azure AD)
        osquery_logs: Path to OSQuery log files
        
    Returns:
        dict: Hunt results with findings and recommendations
    """
    hunter = ScatteredSpiderMacOSHunter(
        crowdstrike_logs=crowdstrike_logs,
        splunk_logs=splunk_logs, 
        sso_logs=sso_logs,
        osquery_logs=osquery_logs
    )
    
    return hunter.run_all_hunts()


def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Scattered Spider macOS Persistence Hunter')
    parser.add_argument('--crowdstrike-logs', help='Path to CrowdStrike log files')
    parser.add_argument('--splunk-logs', help='Path to Splunk log files') 
    parser.add_argument('--sso-logs', help='Path to SSO log files (Okta/Azure AD)')
    parser.add_argument('--osquery-logs', help='Path to OSQuery log files')
    parser.add_argument('--output', default='scattered_spider_hunt_results.json', 
                       help='Output file for hunt results')
    
    args = parser.parse_args()
    
    # Initialize hunter
    hunter = ScatteredSpiderMacOSHunter(
        crowdstrike_logs=args.crowdstrike_logs,
        splunk_logs=args.splunk_logs,
        sso_logs=args.sso_logs,
        osquery_logs=args.osquery_logs
    )
    
    # Run hunt
    results = hunter.run_all_hunts()
    
    # Output results
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[+] Hunt completed!")
    print(f"[+] Risk Score: {results['risk_score']}")
    print(f"[+] Threat Level: {results['threat_level']}")
    print(f"[+] Total Findings: {results['total_findings']}")
    print(f"[+] Results saved to: {args.output}")
    
    # Print high-severity findings
    critical_findings = [f for f in results['detailed_findings'] if f.get('severity') == 'CRITICAL']
    if critical_findings:
        print(f"\n[!] CRITICAL FINDINGS ({len(critical_findings)}):")
        for finding in critical_findings[:5]:  # Show top 5
            print(f"  - {finding['hunt_type']}: {finding['description']}")
    
    return results


if __name__ == "__main__":
    main()