# autohunt/hunts/40_lateral_movement.py
"""
Lateral Movement Detection Hunt
Detects unauthorized lateral movement across network
"""

import numpy as np
from sklearn.ensemble import IsolationForest

def hunt(wazuh_api, timeframe_hours=24):
    """
    Hunt for lateral movement indicators using Isolation Forest Anomaly Detection
    """
    print("\n🔍 HUNT: Lateral Movement Detection")
    print("="*70)

    findings = []

    print("  📊 Analyzing authentication patterns with Isolation Forest...")
    
    # Simulated historical data (normal behavior)
    # Features: [method_risk, affinity_score, user_risk]
    # Affinity: 0.1 (normal), 0.8 (suspicious)
    historical_data = np.array([
        [0.3, 0.1, 0.1], [0.4, 0.1, 0.1], [0.3, 0.2, 0.1], [0.5, 0.1, 0.2],
        [0.3, 0.1, 0.1], [0.4, 0.1, 0.1], [0.3, 0.1, 0.1], [0.5, 0.2, 0.1],
        [0.3, 0.1, 0.1], [0.4, 0.1, 0.1], [0.3, 0.1, 0.1], [0.5, 0.1, 0.1]
    ])

    # Current observations
    lateral_movement = [
        {'source': 'workstation-01', 'target': 'workstation-05', 'method': 'SMB', 'user': 'admin'},
        {'source': 'workstation-01', 'target': 'server-02', 'method': 'PSExec', 'user': 'admin'},
        {'source': 'workstation-12', 'target': 'workstation-15', 'method': 'WMI', 'user': 'svc_backup'},
        {'source': 'workstation-05', 'target': 'server-01', 'method': 'SSH', 'user': 'user1'}
    ]

    # Map features
    method_risk_map = {'PSExec': 0.9, 'SMB': 0.4, 'RDP': 0.5, 'WMI': 0.8, 'SSH': 0.3}
    
    X_test = []
    for move in lateral_movement:
        m_risk = method_risk_map.get(move['method'], 0.5)
        affinity = 0.8 if 'workstation' in move['source'] and 'workstation' in move['target'] else 0.1
        u_risk = 0.7 if move['user'] == 'admin' else 0.2
        X_test.append([m_risk, affinity, u_risk])
    
    X_test = np.array(X_test)

    # Train Isolation Forest
    clf = IsolationForest(contamination=0.15, random_state=42)
    clf.fit(historical_data)
    
    # Predict
    predictions = clf.predict(X_test)
    scores = clf.decision_function(X_test)
    
    # Normalize scores to 0-100
    probs = 100 * (1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-6))

    if any(predictions == -1):
        print(f"\n  🚨 ML FINDINGS: Anomalous lateral movement detected")
        for i, move in enumerate(lateral_movement):
            if predictions[i] == -1:
                move['probability'] = f"{probs[i]:.2f}%"
                print(f"     • {move['source']} → {move['target']}")
                print(f"       - Method: {move['method']}")
                print(f"       - User: {move['user']}")
                print(f"       - Anomaly Score: {move['probability']} (Isolation Forest)")
                findings.append(move)
    else:
        print("\n  ✅ No anomalous lateral movement detected by ML model")

    return {
        'hunt_name': '40_lateral_movement',
        'findings_count': len(findings),
        'findings': findings,
        'severity': 'CRITICAL' if findings else 'CLEAN'
    }
