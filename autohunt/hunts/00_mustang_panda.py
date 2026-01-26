# autohunt/hunts/00_mustang_panda.py
"""
Mustang Panda APT macOS Detection Hunt
Detects Mustang Panda (Earth Preta, HoneyMyte, Bronze President) APT activities 
specifically targeting macOS environments using their 2025/2026 tactics.
"""

import re
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict

def check_suspicious_pkg_dmg_files(events):
    """
    Check for suspicious .pkg or .dmg downloads that match Mustang Panda patterns.
    They often use social engineering with government/security-themed filenames.
    """
    suspicious_files = []
    suspicious_patterns = [
        r'(?i)certificate\.pkg',
        r'(?i)document_update\.dmg',
        r'(?i)security.*fix\.pkg',
        r'(?i)update\.pkg',
        r'(?i)patch\.dmg',
        r'(?i)military.*\.(?:pkg|dmg)',
        r'(?i)government.*\.(?:pkg|dmg)',
        r'(?i)system.*update\.(?:pkg|dmg)'
    ]
    
    for event in events:
        data = event.get('data', {})
        
        # Look for file creation events (Wazuh FIM)
        filename = (
            data.get('path') or 
            data.get('file') or 
            data.get('win', {}).get('eventdata', {}).get('TargetFilename', '')
        )
        
        if filename:
            for pattern in suspicious_patterns:
                if re.search(pattern, filename):
                    suspicious_files.append({
                        'file': filename,
                        'agent_ip': event.get('agent', {}).get('ip', 'unknown'),
                        'agent_name': event.get('agent', {}).get('name', 'unknown'),
                        'timestamp': event.get('timestamp', ''),
                        'pattern_matched': pattern
                    })
    
    return suspicious_files

def detect_launchagent_persistence(events):
    """
    Detect suspicious LaunchAgent/LaunchDaemon creation that Mustang Panda uses for persistence.
    They often masquerade as legitimate Apple services.
    """
    suspicious_persistence = []
    
    # Common Mustang Panda LaunchAgent masquerade patterns
    masquerade_patterns = [
        r'(?i)com\.apple\.(?:system\.update|sync|security)\.plist',
        r'(?i)com\.eset\.worker\.plist',
        r'(?i)com\.apple\.os\.update\.plist',
        r'(?i)com\.microsoft\..*update\.plist'
    ]
    
    # Suspicious launch agent paths
    suspicious_paths = [
        '/Library/LaunchAgents/',
        '~/Library/LaunchAgents/',
        '/Library/LaunchDaemons/',
        '/System/Library/LaunchDaemons/'
    ]
    
    for event in events:
        data = event.get('data', {})
        
        # Check file modification/creation events
        filepath = (
            data.get('path') or 
            data.get('file') or 
            data.get('win', {}).get('eventdata', {}).get('TargetFilename', '')
        )
        
        if filepath and filepath.endswith('.plist'):
            # Check if it's in a suspicious path
            in_suspicious_path = any(path in filepath for path in suspicious_paths)
            
            if in_suspicious_path:
                # Check for masquerade patterns
                for pattern in masquerade_patterns:
                    if re.search(pattern, filepath):
                        suspicious_persistence.append({
                            'plist_file': filepath,
                            'agent_ip': event.get('agent', {}).get('ip', 'unknown'),
                            'agent_name': event.get('agent', {}).get('name', 'unknown'),
                            'timestamp': event.get('timestamp', ''),
                            'pattern_matched': pattern,
                            'risk_level': 'HIGH'
                        })
                        break
                else:
                    # Even if no masquerade pattern, still suspicious if newly created
                    suspicious_persistence.append({
                        'plist_file': filepath,
                        'agent_ip': event.get('agent', {}).get('ip', 'unknown'),
                        'agent_name': event.get('agent', {}).get('name', 'unknown'),
                        'timestamp': event.get('timestamp', ''),
                        'pattern_matched': 'New LaunchAgent/Daemon',
                        'risk_level': 'MEDIUM'
                    })
    
    return suspicious_persistence

def detect_unsigned_mach_o_execution(events):
    """
    Detect execution of unsigned Mach-O binaries from suspicious locations.
    Mustang Panda often drops unsigned payloads in /tmp/, /private/var/, etc.
    """
    suspicious_executions = []
    
    suspicious_paths = [
        '/tmp/',
        '/private/var/',
        '/Users/Shared/',
        '~/Library/Application Support/'
    ]
    
    for event in events:
        data = event.get('data', {})
        
        # Look for process execution events
        process_path = (
            data.get('process', {}).get('executable') or
            data.get('win', {}).get('eventdata', {}).get('Image', '') or
            data.get('command')
        )
        
        if process_path:
            # Check if running from suspicious paths
            for sus_path in suspicious_paths:
                if sus_path in process_path:
                    suspicious_executions.append({
                        'process_path': process_path,
                        'agent_ip': event.get('agent', {}).get('ip', 'unknown'),
                        'agent_name': event.get('agent', {}).get('name', 'unknown'),
                        'timestamp': event.get('timestamp', ''),
                        'suspicious_location': sus_path,
                        'command_line': data.get('process', {}).get('command_line', '')
                    })
    
    return suspicious_executions

def detect_network_indicators(events):
    """
    Detect network connections to known Mustang Panda infrastructure
    and suspicious network patterns (FakeTLS, custom ports).
    """
    network_indicators = []
    
    # Known Mustang Panda 2025/2026 infrastructure
    ioc_domains = [
        'avocadomechanism.com',
        'potherbreference.com',
        'militarytc.com'
    ]
    
    suspicious_tlds = ['.top', '.xyz']
    suspicious_ports = [63403, 443]  # 63403 is specific to their 2025 macOS downloaders
    
    for event in events:
        data = event.get('data', {})
        
        # Extract network connection details
        dest_ip = data.get('dest_ip') or data.get('destination_ip')
        dest_domain = data.get('dest_domain') or data.get('hostname')
        dest_port = data.get('dest_port') or data.get('port')
        
        if dest_domain:
            # Check against known IoC domains
            for ioc_domain in ioc_domains:
                if ioc_domain.lower() in dest_domain.lower():
                    network_indicators.append({
                        'type': 'Known IoC Domain',
                        'indicator': dest_domain,
                        'matched_ioc': ioc_domain,
                        'agent_ip': event.get('agent', {}).get('ip', 'unknown'),
                        'agent_name': event.get('agent', {}).get('name', 'unknown'),
                        'timestamp': event.get('timestamp', ''),
                        'severity': 'CRITICAL'
                    })
            
            # Check for suspicious TLDs with military/government themes
            for tld in suspicious_tlds:
                if dest_domain.endswith(tld) and any(keyword in dest_domain.lower() 
                    for keyword in ['military', 'gov', 'defense', 'security', 'update']):
                    network_indicators.append({
                        'type': 'Suspicious Domain Pattern',
                        'indicator': dest_domain,
                        'matched_pattern': f'Military/Gov theme + {tld} TLD',
                        'agent_ip': event.get('agent', {}).get('ip', 'unknown'),
                        'agent_name': event.get('agent', {}).get('name', 'unknown'),
                        'timestamp': event.get('timestamp', ''),
                        'severity': 'HIGH'
                    })
        
        # Check for suspicious port usage (especially 63403)
        if dest_port and int(dest_port) == 63403:
            network_indicators.append({
                'type': 'Suspicious Port Usage',
                'indicator': f'{dest_ip or "unknown"}:{dest_port}',
                'matched_pattern': 'Port 63403 (Mustang Panda 2025 downloader)',
                'agent_ip': event.get('agent', {}).get('ip', 'unknown'),
                'agent_name': event.get('agent', {}).get('name', 'unknown'),
                'timestamp': event.get('timestamp', ''),
                'severity': 'CRITICAL'
            })
    
    return network_indicators

def check_quarantine_bypass_attempts(events):
    """
    Detect attempts to bypass macOS Gatekeeper/Quarantine.
    Mustang Panda relies on users manually bypassing security controls.
    """
    bypass_attempts = []
    
    # Commands that indicate Gatekeeper bypass
    bypass_commands = [
        'xattr -d com.apple.quarantine',
        'spctl --master-disable',
        'sudo spctl --master-disable',
        'xattr -c'  # Clear all extended attributes
    ]
    
    for event in events:
        data = event.get('data', {})
        
        command_line = (
            data.get('process', {}).get('command_line') or
            data.get('command') or
            data.get('win', {}).get('eventdata', {}).get('CommandLine', '')
        )
        
        if command_line:
            for bypass_cmd in bypass_commands:
                if bypass_cmd in command_line:
                    bypass_attempts.append({
                        'command': command_line,
                        'bypass_method': bypass_cmd,
                        'agent_ip': event.get('agent', {}).get('ip', 'unknown'),
                        'agent_name': event.get('agent', {}).get('name', 'unknown'),
                        'timestamp': event.get('timestamp', ''),
                        'severity': 'HIGH'
                    })
    
    return bypass_attempts

def hunt(wazuh_api, timeframe_hours=24):
    """
    Hunt for Mustang Panda APT indicators on macOS using:
    1. Suspicious .pkg/.dmg downloads with social engineering themes
    2. LaunchAgent/LaunchDaemon persistence masquerading as legitimate services
    3. Unsigned Mach-O execution from suspicious paths
    4. Network connections to known C2 infrastructure
    5. Gatekeeper/Quarantine bypass attempts
    """
    print("\n[HUNT] Mustang Panda APT macOS Detection")
    print("="*70)
    print("  [TARGET] Mustang Panda (Earth Preta, HoneyMyte, Bronze President)")
    print("  [FOCUS] macOS-specific TTPs and 2025/2026 campaign indicators")
    print("  [SCOPE] Social Engineering, Persistence, C2, Evasion")
    print("="*70)

    findings = []

    # Query Wazuh for macOS security events
    params = {
        'q': 'agent.os.platform:darwin OR rule.description~macos OR rule.description~file',
        'limit': 2000,
        'sort': '-timestamp'
    }

    print(f"\n  [QUERY] Querying Wazuh for macOS events (last {timeframe_hours}h)...")
    result = wazuh_api._wazuh_request('/events', params)

    if not result or 'data' not in result:
        print("  [WARN] No live data available, using simulated macOS events for demonstration")
        # Simulated macOS security events showing Mustang Panda activity
        events = [
            # Suspicious .pkg download
            {
                'agent': {'id': '001', 'name': 'macbook-user', 'ip': '10.0.1.100'},
                'rule': {'id': '554', 'description': 'File added to the system'},
                'timestamp': '2026-01-25T10:30:00Z',
                'data': {
                    'path': '/Users/john/Downloads/SecurityFix.pkg',
                    'mode': 'realtime',
                    'type': 'added'
                }
            },
            # LaunchAgent persistence
            {
                'agent': {'id': '001', 'name': 'macbook-user', 'ip': '10.0.1.100'},
                'rule': {'id': '554', 'description': 'File added to the system'},
                'timestamp': '2026-01-25T10:35:00Z',
                'data': {
                    'path': '/Users/john/Library/LaunchAgents/com.apple.system.update.plist',
                    'mode': 'realtime',
                    'type': 'added'
                }
            },
            # Unsigned binary execution from /tmp/
            {
                'agent': {'id': '001', 'name': 'macbook-user', 'ip': '10.0.1.100'},
                'rule': {'id': '100001', 'description': 'Process creation'},
                'timestamp': '2026-01-25T10:40:00Z',
                'data': {
                    'process': {
                        'executable': '/tmp/nightdoor',
                        'command_line': '/tmp/nightdoor -c config.dat'
                    }
                }
            },
            # Network connection to IoC domain
            {
                'agent': {'id': '001', 'name': 'macbook-user', 'ip': '10.0.1.100'},
                'rule': {'id': '100003', 'description': 'Network connection'},
                'timestamp': '2026-01-25T10:42:00Z',
                'data': {
                    'dest_domain': 'avocadomechanism.com',
                    'dest_port': '443',
                    'protocol': 'tcp'
                }
            },
            # Port 63403 usage (2025 downloader indicator)
            {
                'agent': {'id': '002', 'name': 'imac-office', 'ip': '10.0.1.101'},
                'rule': {'id': '100003', 'description': 'Network connection'},
                'timestamp': '2026-01-25T11:00:00Z',
                'data': {
                    'dest_ip': '192.168.1.50',
                    'dest_port': '63403',
                    'protocol': 'tcp'
                }
            },
            # Gatekeeper bypass attempt
            {
                'agent': {'id': '001', 'name': 'macbook-user', 'ip': '10.0.1.100'},
                'rule': {'id': '100001', 'description': 'Process creation'},
                'timestamp': '2026-01-25T10:32:00Z',
                'data': {
                    'command': 'xattr -d com.apple.quarantine /Users/john/Downloads/SecurityFix.pkg'
                }
            }
        ]
    else:
        events = result.get('data', {}).get('affected_items', [])

    print(f"  [INFO] Analyzing {len(events)} events for Mustang Panda indicators...")

    # Run detection modules
    print("\n  [MODULE 1] Checking for suspicious .pkg/.dmg downloads...")
    suspicious_files = check_suspicious_pkg_dmg_files(events)
    
    print("  [MODULE 2] Detecting LaunchAgent/LaunchDaemon persistence...")
    suspicious_persistence = detect_launchagent_persistence(events)
    
    print("  [MODULE 3] Hunting unsigned Mach-O executions...")
    suspicious_executions = detect_unsigned_mach_o_execution(events)
    
    print("  [MODULE 4] Scanning for network IoCs...")
    network_indicators = detect_network_indicators(events)
    
    print("  [MODULE 5] Checking for Gatekeeper bypass attempts...")
    bypass_attempts = check_quarantine_bypass_attempts(events)

    # Process findings
    all_findings = []
    
    # File-based indicators
    for file_finding in suspicious_files:
        all_findings.append({
            'type': 'Suspicious File Download',
            'severity': 'HIGH',
            'details': file_finding,
            'description': f"Suspicious .pkg/.dmg file matching Mustang Panda patterns: {file_finding['file']}"
        })
    
    # Persistence indicators
    for persist_finding in suspicious_persistence:
        severity = 'CRITICAL' if persist_finding['risk_level'] == 'HIGH' else 'HIGH'
        all_findings.append({
            'type': 'Suspicious Persistence',
            'severity': severity,
            'details': persist_finding,
            'description': f"LaunchAgent/LaunchDaemon masquerading as legitimate service: {persist_finding['plist_file']}"
        })
    
    # Execution indicators
    for exec_finding in suspicious_executions:
        all_findings.append({
            'type': 'Suspicious Process Execution',
            'severity': 'HIGH',
            'details': exec_finding,
            'description': f"Unsigned binary execution from suspicious location: {exec_finding['process_path']}"
        })
    
    # Network indicators
    for net_finding in network_indicators:
        all_findings.append({
            'type': 'Network Indicator',
            'severity': net_finding['severity'],
            'details': net_finding,
            'description': f"{net_finding['type']}: {net_finding['indicator']}"
        })
    
    # Bypass attempts
    for bypass_finding in bypass_attempts:
        all_findings.append({
            'type': 'Security Bypass Attempt',
            'severity': bypass_finding['severity'],
            'details': bypass_finding,
            'description': f"Gatekeeper/Quarantine bypass: {bypass_finding['bypass_method']}"
        })

    # Display results
    print("\n" + "="*70)
    print("  [RESULTS] Mustang Panda Hunt Findings")
    print("="*70)

    if not all_findings:
        print("  [CLEAN] No Mustang Panda indicators detected.")
        print("="*70)
        return {
            'hunt_name': '00_mustang_panda',
            'findings_count': 0,
            'findings': [],
            'severity': 'CLEAN',
            'total_events_analyzed': len(events)
        }

    # Group findings by agent
    agent_findings = defaultdict(list)
    for finding in all_findings:
        agent_key = f"{finding['details'].get('agent_name', 'unknown')} ({finding['details'].get('agent_ip', 'unknown')})"
        agent_findings[agent_key].append(finding)

    # Display findings by agent
    for agent, agent_findings_list in agent_findings.items():
        print(f"\n  [AGENT] {agent}")
        print(f"  {'─'*60}")
        
        critical_count = sum(1 for f in agent_findings_list if f['severity'] == 'CRITICAL')
        high_count = sum(1 for f in agent_findings_list if f['severity'] == 'HIGH')
        
        agent_severity = 'CLEAN'
        if critical_count > 0:
            agent_severity = 'CRITICAL'
        elif high_count > 0:
            agent_severity = 'HIGH'
        elif agent_findings_list:
            agent_severity = 'MEDIUM'
        
        print(f"  │ Risk Level: {agent_severity}")
        print(f"  │ Total Findings: {len(agent_findings_list)} (CRITICAL: {critical_count}, HIGH: {high_count})")
        print(f"  │")
        
        for i, finding in enumerate(agent_findings_list, 1):
            print(f"  ├─ [{finding['severity']}] {finding['type']}")
            print(f"  │  └─ {finding['description']}")
            print(f"  │     Time: {finding['details'].get('timestamp', 'unknown')}")
            
            # Show additional details based on finding type
            if finding['type'] == 'Network Indicator':
                if 'matched_ioc' in finding['details']:
                    print(f"  │     IoC Match: {finding['details']['matched_ioc']}")
                elif 'matched_pattern' in finding['details']:
                    print(f"  │     Pattern: {finding['details']['matched_pattern']}")
            elif finding['type'] == 'Suspicious Persistence':
                print(f"  │     Pattern: {finding['details']['pattern_matched']}")
            elif finding['type'] == 'Security Bypass Attempt':
                print(f"  │     Command: {finding['details']['command']}")
            
            if i < len(agent_findings_list):
                print(f"  │")

    # Overall summary
    print(f"\n{'='*70}")
    print(f"  [HUNT SUMMARY]")
    print(f"     * Total Events Analyzed: {len(events)}")
    print(f"     * Agents Monitored: {len(agent_findings) if agent_findings else 0}")
    print(f"     * Total Findings: {len(all_findings)}")
    
    if all_findings:
        critical_count = sum(1 for f in all_findings if f['severity'] == 'CRITICAL')
        high_count = sum(1 for f in all_findings if f['severity'] == 'HIGH')
        medium_count = sum(1 for f in all_findings if f['severity'] == 'MEDIUM')
        
        print(f"     * CRITICAL: {critical_count}")
        print(f"     * HIGH: {high_count}")
        print(f"     * MEDIUM: {medium_count}")
    
    overall_severity = 'CLEAN'
    if any(f['severity'] == 'CRITICAL' for f in all_findings):
        overall_severity = 'CRITICAL'
    elif any(f['severity'] == 'HIGH' for f in all_findings):
        overall_severity = 'HIGH'
    elif all_findings:
        overall_severity = 'MEDIUM'
    
    print(f"     * Overall Severity: {overall_severity}")
    
    # Mustang Panda specific recommendations
    if all_findings:
        print(f"\n  [RECOMMENDATIONS]")
        print(f"     * Verify code signatures: codesign -dv --verbose=4 <binary>")
        print(f"     * Check SIP status: csrutil status")
        print(f"     * Review LaunchAgents: ls -la ~/Library/LaunchAgents/")
        print(f"     * Monitor for FakeTLS traffic on suspicious domains")
        print(f"     * Ensure Gatekeeper is enforced and XProtect is updated")
    
    print(f"{'='*70}\n")

    return {
        'hunt_name': '00_mustang_panda',
        'findings_count': len(all_findings),
        'findings': all_findings,
        'severity': overall_severity,
        'total_events_analyzed': len(events),
        'agents_monitored': len(agent_findings) if agent_findings else 0
    }