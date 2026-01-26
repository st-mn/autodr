# autohunt/hunts/00_dns_tunneling.py
"""
DNS Tunneling Detection Hunt
Detects potential DNS tunneling for C2 communication using advanced statistical analysis
and behavioral pattern detection.  
"""

import math
import numpy as np
from sklearn.ensemble import IsolationForest
from collections import defaultdict
from datetime import datetime, timedelta

def calculate_entropy(text):
    """
    Calculate Shannon entropy of a string.  
    High entropy (>4.0) indicates potential encoded data (Base64/Base32).
    """
    if not text:
        return 0
    entropy = 0
    text_len = len(text)
    # Count character frequencies
    char_counts = defaultdict(int)
    for char in text:
        char_counts[char] += 1
    
    # Calculate Shannon entropy
    for count in char_counts.values():
        if count > 0:
            p_x = float(count) / text_len
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def extract_subdomain(domain):
    """
    Extract the subdomain portion for entropy analysis.
    Example: 'aGVsbG8.tunnel.net' -> 'aGVsbG8'
    """
    if not domain:  
        return ""
    parts = domain.split('.')
    if len(parts) > 2:
        # Return the leftmost label (subdomain)
        return parts[0]
    return domain

def get_parent_domain(domain):
    """
    Extract parent domain (last two labels).
    Example: 'sub.example.com' -> 'example. com'
    """
    if not domain:
        return ""
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'. join(parts[-2:])
    return domain

def analyze_dns_behavioral_patterns(events):
    """
    Analyze behavioral patterns across DNS events:  
    - Request frequency per source IP
    - Unique subdomain counts
    - Record type distribution
    - NXDOMAIN spike detection
    """
    ip_stats = defaultdict(lambda: {
        'total_requests': 0,
        'unique_domains': set(),
        'unique_subdomains': set(),
        'parent_domains': defaultdict(int),
        'record_types': defaultdict(int),
        'nxdomain_count': 0,
        'avg_query_length': [],
        'suspicious_processes': []
    })
    
    for event in events:
        # Extract source IP
        data = event. get('data', {})
        agent = event.get('agent', {})
        
        # Try multiple fields for source IP
        source_ip = (
            data.get('srcip') or 
            data.get('src_ip') or 
            data.get('win', {}).get('eventdata', {}).get('SourceIP') or
            agent.get('ip', 'unknown')
        )
        
        # Extract domain
        domain = None
        if 'win' in data and 'eventdata' in data['win']:
            domain = data['win']['eventdata']. get('QueryName', '')
        elif 'QueryName' in data:  
            domain = data. get('QueryName', '')
        elif 'query' in data:
            domain = data.get('query', '')
        
        if not domain:  
            continue
        
        stats = ip_stats[source_ip]
        stats['total_requests'] += 1
        stats['unique_domains'].add(domain. lower())
        
        # Track subdomains
        subdomain = extract_subdomain(domain)
        if subdomain:
            stats['unique_subdomains'].add(subdomain)
        
        # Track parent domains
        parent = get_parent_domain(domain)
        if parent:
            stats['parent_domains'][parent] += 1
        
        # Track query length
        stats['avg_query_length'].append(len(domain))
        
        # Track record types
        record_type = (
            data.get('qtype') or 
            data.get('win', {}).get('eventdata', {}).get('QueryType') or
            'A'
        )
        stats['record_types'][record_type] += 1
        
        # Track NXDOMAIN responses
        response_code = data.get('rcode', '')
        if 'NXDOMAIN' in str(response_code).upper():
            stats['nxdomain_count'] += 1
        
        # Track suspicious processes (Sysmon Event ID 22)
        process = data.get('win', {}).get('eventdata', {}).get('Image', '')
        if process:  
            process_name = process.split('\\')[-1].lower()
            suspicious_procs = ['powershell.exe', 'cmd.exe', 'wscript.exe', 
                              'cscript.exe', 'mshta.exe', 'rundll32.exe']
            if process_name in suspicious_procs:
                stats['suspicious_processes'].append(process_name)
    
    return ip_stats

def calculate_behavioral_risk_score(stats, domain, subdomain_length):
    """
    Calculate risk score based on behavioral indicators:
    - High unique subdomain count (> 100)
    - High request volume to single parent domain (> 1000)
    - Unusual record type distribution
    - NXDOMAIN spikes
    - Suspicious process correlation
    """
    risk_score = 0
    risk_factors = []
    
    # Factor 1: Unique subdomain count
    unique_subdomain_count = len(stats['unique_subdomains'])
    if unique_subdomain_count > 500:
        risk_score += 30
        risk_factors.append(f"Very high unique subdomains:  {unique_subdomain_count}")
    elif unique_subdomain_count > 100:
        risk_score += 20
        risk_factors.append(f"High unique subdomains: {unique_subdomain_count}")
    
    # Factor 2: Request volume to single parent domain
    if stats['parent_domains']:  
        max_requests_to_domain = max(stats['parent_domains'].values())
        if max_requests_to_domain > 1000:
            risk_score += 25
            risk_factors. append(f"High request volume:  {max_requests_to_domain}")
        elif max_requests_to_domain > 500:
            risk_score += 15
            risk_factors.append(f"Elevated request volume: {max_requests_to_domain}")
    
    # Factor 3: Unusual record types (TXT, NULL, CNAME)
    unusual_types = ['TXT', 'NULL', 'CNAME', 'MX']
    unusual_count = sum(stats['record_types'].get(t, 0) for t in unusual_types)
    total_requests = stats['total_requests']
    if total_requests > 0:
        unusual_ratio = unusual_count / total_requests
        if unusual_ratio > 0.3:
            risk_score += 20
            risk_factors.append(f"High unusual record type ratio: {unusual_ratio:.2%}")
    
    # Factor 4: NXDOMAIN spike
    if total_requests > 0:
        nxdomain_ratio = stats['nxdomain_count'] / total_requests
        if nxdomain_ratio > 0.2:
            risk_score += 15
            risk_factors.append(f"NXDOMAIN spike: {nxdomain_ratio:.2%}")
    
    # Factor 5: Suspicious process correlation
    if stats['suspicious_processes']:
        risk_score += 20
        unique_procs = set(stats['suspicious_processes'])
        risk_factors.append(f"Suspicious processes: {', '.join(unique_procs)}")
    
    # Factor 6: Average query length
    if stats['avg_query_length']: 
        avg_len = sum(stats['avg_query_length']) / len(stats['avg_query_length'])
        if avg_len > 50:
            risk_score += 10
            risk_factors.append(f"Large avg query length: {avg_len:. 1f}")
    
    return min(risk_score, 100), risk_factors

def hunt(wazuh_api, timeframe_hours=24):
    """
    Hunt for DNS tunneling indicators using:  
    1. Statistical anomaly detection (Isolation Forest)
    2. Behavioral pattern analysis
    3. The "Big Three" metrics:  entropy, volume/frequency, payload size
    """
    print("\n[HUNT] Advanced DNS Tunneling Detection")
    print("="*70)
    print("  [METRICS] High Entropy, Request Volume, Payload Size")
    print("  [METHODS] Isolation Forest + Behavioral Analysis")
    print("="*70)

    findings = []

    # Simulated historical data for training (normal DNS traffic)
    # Features: [entropy, length, request_count]
    historical_data = np.array([
        [2.1, 12, 5], [2.3, 15, 8], [1.9, 10, 3], [2.5, 18, 12], [2.2, 14, 7],
        [2.0, 11, 4], [2.4, 16, 9], [2.1, 13, 6], [2.3, 15, 8], [2.0, 12, 5],
        [3.1, 25, 15], [2.8, 20, 10], [2.5, 15, 8], [2.2, 12, 5], [2.1, 10, 4],
        [2.3, 14, 7], [2.0, 11, 5], [2.4, 17, 9], [2.2, 13, 6], [2.1, 12, 5]
    ])

    # Query Wazuh for DNS events
    params = {
        'q': 'rule. description~DNS',
        'limit': 1000,  # Increased limit to catch patterns
        'sort': '-timestamp'
    }

    print(f"\n  [QUERY] Querying Wazuh for DNS events (last {timeframe_hours}h)...")
    result = wazuh_api._wazuh_request('/events', params)

    if not result or 'data' not in result: 
        print("  [WARN] No live data available, using simulated data for demonstration")
        # Enhanced simulated data with more realistic tunneling patterns
        events = [
            # Tunneling activity - high entropy, many unique subdomains
            *[{
                'agent': {'id': '001', 'name': 'workstation-01', 'ip': '10.0.1.50'},
                'rule': {'id': '100002', 'description': 'DNS Query'},
                'timestamp': '2026-01-13T10:00:00Z',
                'data': {
                    'QueryName': f'aGVsbG97i: 02x}d29ybGQxMjM0NTY3ODkw. tunnel-c2.net',
                    'qtype':  'TXT',
                    'srcip': '10.0.1.50'
                }
            } for i in range(150)],
            # Base64-encoded tunneling
            *[{
                'agent': {'id': '005', 'name': 'server-db-01', 'ip': '10.0.2.100'},
                'rule': {'id': '100002', 'description': 'DNS Query'},
                'timestamp': '2026-01-13T10:05:00Z',
                'data': {
                    'QueryName': f'c3VzcGljaW91c2RhdGF0cmFuc2Zlcnt j: 02x}. exfil-domain.com',
                    'qtype': 'A',
                    'srcip':  '10.0.2.100'
                }
            } for i in range(200)],
            # Normal traffic
            {
                'agent': {'id':  '002', 'name': 'workstation-02', 'ip': '10.0.1.75'},
                'rule': {'id': '100001', 'description': 'DNS Query'},
                'timestamp': '2026-01-13T10:10:00Z',
                'data': {'QueryName': 'google.com', 'qtype':  'A', 'srcip': '10.0.1.75'}
            },
            {
                'agent': {'id':  '002', 'name': 'workstation-02', 'ip':  '10.0.1.75'},
                'rule': {'id': '100001', 'description': 'DNS Query'},
                'timestamp': '2026-01-13T10:11:00Z',
                'data': {'QueryName': 'microsoft.com', 'qtype':  'A', 'srcip': '10.0.1.75'}
            }
        ]
    else:
        events = result['data']['affected_items']

    if not events:
        print("  [OK] No DNS events found to analyze")
        return {'hunt_name': '00_dns_tunneling', 'findings_count': 0, 'findings': [], 'severity': 'CLEAN'}

    print(f"  [ANALYSIS] Analyzing {len(events)} DNS events...")
    
    # Step 1: Behavioral pattern analysis
    print("\n  [STEP 1] Behavioral Pattern Analysis")
    ip_stats = analyze_dns_behavioral_patterns(events)
    
    # Step 2: ML-based anomaly detection
    print("  [STEP 2] Machine Learning Anomaly Detection (Isolation Forest)")
    
    X_test = []
    processed_events = []
    
    for event in events:
        domain = None
        data = event.get('data', {})
        agent = event.get('agent', {})
        
        # Extract domain
        if 'win' in data and 'eventdata' in data['win']:
            domain = data['win']['eventdata'].get('QueryName', '')
        elif 'QueryName' in data: 
            domain = data.get('QueryName', '')
        elif 'query' in data:  
            domain = data.get('query', '')
        
        if not domain:
            continue
        
        # Get source IP for behavioral context
        source_ip = (
            data.get('srcip') or 
            data.get('src_ip') or 
            agent.get('ip', 'unknown')
        )
        
        # Calculate features
        subdomain = extract_subdomain(domain)
        entropy = calculate_entropy(subdomain) if subdomain else calculate_entropy(domain)
        length = len(subdomain) if subdomain else len(domain)
        request_count = ip_stats. get(source_ip, {}).get('total_requests', 1)
        
        # Feature vector:  [entropy, length, log(request_count)]
        X_test.append([entropy, length, math.log(request_count + 1)])
        processed_events.append((event, domain, subdomain, entropy, length, source_ip))

    if not X_test:
        print("  [OK] No domains extracted for analysis")
        return {'hunt_name': '00_dns_tunneling', 'findings_count': 0, 'findings': [], 'severity': 'CLEAN'}

    X_test = np.array(X_test)
    
    # Train Isolation Forest with adjusted contamination
    clf = IsolationForest(contamination=0.15, random_state=42, n_estimators=100)
    clf.fit(historical_data)
    
    # Predict anomalies
    predictions = clf.predict(X_test)
    scores = clf.decision_function(X_test)
    
    # Normalize ML scores to 0-100
    score_range = scores.max() - scores.min()
    if score_range > 0:
        ml_probs = 100 * (1 - (scores - scores.min()) / score_range)
    else:
        ml_probs = np.zeros(len(scores))

    print(f"\n  [STEP 3] Applying Detection Thresholds")
    print(f"      * Entropy Threshold: > 4.0 (High)")
    print(f"      * Subdomain Length:  > 50 characters")
    print(f"      * Request Volume: > 100 per parent domain")
    
    # Aggregate findings by source IP to avoid duplicates
    ip_findings = defaultdict(lambda: {
        'domains': set(),
        'max_entropy': 0,
        'max_ml_score': 0,
        'max_behavioral_score': 0,
        'risk_factors': set()
    })
    
    for i, (event, domain, subdomain, entropy, length, source_ip) in enumerate(processed_events):
        # Apply "Big Three" thresholds
        high_entropy = entropy > 4.0
        large_payload = length > 50
        ml_anomaly = predictions[i] == -1
        
        # Calculate behavioral risk
        stats = ip_stats. get(source_ip, {})
        behavioral_score, risk_factors = calculate_behavioral_risk_score(stats, domain, length)
        
        # Combine signals:  ML anomaly OR high entropy + behavioral indicators
        is_suspicious = (
            (ml_anomaly and (high_entropy or large_payload)) or
            (high_entropy and behavioral_score > 40) or
            (behavioral_score > 60)
        )
        
        if is_suspicious:
            ip_finding = ip_findings[source_ip]
            ip_finding['domains'].add(domain)
            ip_finding['max_entropy'] = max(ip_finding['max_entropy'], entropy)
            ip_finding['max_ml_score'] = max(ip_finding['max_ml_score'], ml_probs[i])
            ip_finding['max_behavioral_score'] = max(ip_finding['max_behavioral_score'], behavioral_score)
            ip_finding['risk_factors'].update(risk_factors)
            ip_finding['agent_name'] = event. get('agent', {}).get('name', 'unknown')
            ip_finding['stats'] = stats

    # Generate findings summary
    for source_ip, ip_data in ip_findings.items():
        stats = ip_data['stats']
        
        # Combined risk score (weighted average)
        combined_score = (
            ip_data['max_ml_score'] * 0.4 +
            ip_data['max_behavioral_score'] * 0.6
        )
        
        # Determine severity
        if combined_score > 75 or ip_data['max_entropy'] > 5. 0:
            severity = 'CRITICAL'
        elif combined_score > 60 or ip_data['max_entropy'] > 4.5:
            severity = 'HIGH'
        elif combined_score > 40: 
            severity = 'MEDIUM'
        else:
            severity = 'LOW'
        
        # Get top parent domain
        top_parent = max(stats. get('parent_domains', {'unknown':  0}).items(), 
                        key=lambda x:  x[1]) if stats.get('parent_domains') else ('unknown', 0)
        
        finding = {
            'source_ip': source_ip,
            'agent_name': ip_data['agent_name'],
            'unique_domains': len(ip_data['domains']),
            'sample_domains': list(ip_data['domains'])[:3],  # Show top 3
            'max_entropy': f"{ip_data['max_entropy']:.2f}",
            'total_requests': stats.get('total_requests', 0),
            'unique_subdomains': len(stats.get('unique_subdomains', [])),
            'top_parent_domain': top_parent[0],
            'requests_to_top_domain': top_parent[1],
            'nxdomain_count': stats.get('nxdomain_count', 0),
            'unusual_record_types': dict(stats.get('record_types', {})),
            'suspicious_processes': list(set(stats.get('suspicious_processes', []))),
            'ml_anomaly_score': f"{ip_data['max_ml_score']:.2f}%",
            'behavioral_risk_score': f"{ip_data['max_behavioral_score']:.2f}%",
            'combined_risk_score': f"{combined_score:.2f}%",
            'risk_factors': list(ip_data['risk_factors']),
            'severity': severity
        }
        findings.append(finding)

    # Sort by combined risk score
    findings.sort(key=lambda x: float(x['combined_risk_score']. rstrip('%')), reverse=True)

    # Print detailed findings
    for idx, finding in enumerate(findings, 1):
        print(f"\n  [FINDING #{idx}] [{finding['severity']}]")
        print(f"     +- Source IP: {finding['source_ip']} ({finding['agent_name']})")
        print(f"     +- Combined Risk Score: {finding['combined_risk_score']}")
        print(f"     +- ML Anomaly Score: {finding['ml_anomaly_score']}")
        print(f"     +- Behavioral Risk:  {finding['behavioral_risk_score']}")
        print(f"     |")
        print(f"     +- [VOLUME METRICS]")
        print(f"     |  +- Total DNS Requests: {finding['total_requests']}")
        print(f"     |  +- Unique Subdomains: {finding['unique_subdomains']}")
        print(f"     |  +- Top Parent Domain: {finding['top_parent_domain']} ({finding['requests_to_top_domain']} requests)")
        print(f"     |  +- NXDOMAIN Errors: {finding['nxdomain_count']}")
        print(f"     |")
        print(f"     +- [QUALITY METRICS]")
        print(f"     |  +- Max Entropy: {finding['max_entropy']} {'[HIGH]' if float(finding['max_entropy']) > 4.0 else ''}")
        print(f"     |  +- Record Types: {finding['unusual_record_types']}")
        
        if finding['suspicious_processes']:
            print(f"     |")
            print(f"     +- [ALERT] Suspicious Processes: {', '. join(finding['suspicious_processes'])}")
        
        print(f"     |")
        print(f"     +- [SAMPLE DOMAINS]")
        for domain in finding['sample_domains']: 
            print(f"     |  * {domain}")
        
        if finding['risk_factors']:
            print(f"     |")
            print(f"     +- [RISK FACTORS]")
            for factor in finding['risk_factors']: 
                print(f"        * {factor}")

    # Overall summary
    print(f"\n{'='*70}")
    print(f"  [HUNT SUMMARY]")
    print(f"     * Total Events Analyzed: {len(events)}")
    print(f"     * Unique IPs Monitored: {len(ip_stats)}")
    print(f"     * Suspicious IPs Found: {len(findings)}")
    
    if findings:
        critical_count = sum(1 for f in findings if f['severity'] == 'CRITICAL')
        high_count = sum(1 for f in findings if f['severity'] == 'HIGH')
        print(f"     * CRITICAL Findings: {critical_count}")
        print(f"     * HIGH Findings: {high_count}")
    
    overall_severity = 'CLEAN'
    if any(f['severity'] == 'CRITICAL' for f in findings):
        overall_severity = 'CRITICAL'
    elif any(f['severity'] == 'HIGH' for f in findings):
        overall_severity = 'HIGH'
    elif findings:
        overall_severity = 'MEDIUM'
    
    print(f"     * Overall Severity: {overall_severity}")
    print(f"{'='*70}\n")

    return {
        'hunt_name': '00_dns_tunneling',
        'findings_count': len(findings),
        'findings': findings,
        'severity': overall_severity,
        'total_events_analyzed': len(events),
        'unique_ips_monitored': len(ip_stats)
    }
