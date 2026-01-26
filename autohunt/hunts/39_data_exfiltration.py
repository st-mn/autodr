# autohunt/hunts/data_exfiltration.py
"""
Data Exfiltration Detection Hunt
Detects potential data exfiltration attempts
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

def hunt(wazuh_api, timeframe_hours=24):
    """
    Hunt for data exfiltration indicators using Isolation Forest Anomaly Detection
    """
    print("\n🔍 HUNT: Data Exfiltration Detection")
    print("="*70)

    findings = []

    print("  📊 Analyzing network traffic patterns with Isolation Forest...")
    
    # Simulated historical data for training (in a real scenario, this would be fetched from Wazuh/Indexer)
    # Features: [size_mb, protocol_risk_score, destination_risk_score]
    historical_data = np.array([
        [50, 0.2, 0.1], [120, 0.2, 0.1], [30, 0.3, 0.2], [200, 0.2, 0.1],
        [15, 0.2, 0.1], [45, 0.3, 0.2], [80, 0.2, 0.1], [10, 0.2, 0.1],
        [300, 0.4, 0.3], [50, 0.2, 0.1], [20, 0.2, 0.1], [100, 0.2, 0.1]
    ])
    
    # Current observations to analyze
    observations = [
        {'host': 'workstation-03', 'destination': 'mega.nz', 'size_mb': 2500, 'protocol': 'HTTPS'},
        {'host': 'workstation-07', 'destination': 'unknown-ftp.com', 'size_mb': 1800, 'protocol': 'FTP'},
        {'host': 'server-01', 'destination': 'backup-site.xyz', 'size_mb': 4500, 'protocol': 'SFTP'},
        {'host': 'workstation-12', 'destination': 'internal-share', 'size_mb': 50, 'protocol': 'HTTPS'}
    ]
    
    # Map protocols to risk scores
    protocol_map = {'HTTPS': 0.2, 'FTP': 0.8, 'SFTP': 0.3, 'SCP': 0.4}
    
    # Prepare features for inference
    X_test = []
    for obs in observations:
        p_risk = protocol_map.get(obs['protocol'], 0.5)
        d_risk = 0.8 if 'unknown' in obs['destination'] or '.xyz' in obs['destination'] else 0.1
        X_test.append([obs['size_mb'], p_risk, d_risk])
    
    X_test = np.array(X_test)
    
    # Train Isolation Forest
    clf = IsolationForest(contamination=0.1, random_state=42)
    clf.fit(historical_data)
    
    # Predict anomalies (-1 for anomaly, 1 for normal)
    predictions = clf.predict(X_test)
    scores = clf.decision_function(X_test) # Lower is more anomalous
    
    # Convert decision scores to a 0-100 probability-like score
    # decision_function returns values in range roughly [-0.5, 0.5]
    # We normalize it so that lower scores (anomalies) get higher probability
    probs = 100 * (1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-6))

    if any(predictions == -1):
        print(f"\n  🚨 ML FINDINGS: Anomalous exfiltration attempts detected")
        for i, obs in enumerate(observations):
            if predictions[i] == -1:
                obs['probability'] = f"{probs[i]:.2f}%"
                print(f"     • Host: {obs['host']}")
                print(f"       - Destination: {obs['destination']}")
                print(f"       - Data size: {obs['size_mb']} MB")
                print(f"       - Protocol: {obs['protocol']}")
                print(f"       - Anomaly Score: {obs['probability']} (Isolation Forest)")
                findings.append(obs)
    else:
        print("\n  ✅ No anomalous data exfiltration detected by ML model")

    return {
        'hunt_name': 'data_exfiltration',
        'findings_count': len(findings),
        'findings': findings,
        'severity': 'CRITICAL' if findings else 'CLEAN'
    }
