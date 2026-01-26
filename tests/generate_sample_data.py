# generate_sample_data.py
"""Generate sample security events for testing"""

import json
from datetime import datetime, timedelta
import random

# Sample malicious IPs
malicious_ips = ['192.168.1.100', '10.0.0.50', '172.16.0.200']

# Sample alerts
sample_alerts = []

alert_types = [
    "Brute force attack detected",
    "Suspicious PowerShell execution",
    "Port scan detected",
    "Malware hash detected",
    "Lateral movement via SMB",
    "Privilege escalation attempt",
    "Data exfiltration detected"
]

for i in range(50):
    alert = {
        'timestamp': (datetime.now() - timedelta(hours=random.randint(1, 24))).isoformat(),
        'agent': {'name': f'agent-{random.randint(1,5)}'},
        'rule': {
            'description': random.choice(alert_types),
            'level': random.choice([10, 11, 12, 13, 14, 15]),
            'groups': ['attack', 'malware', 'authentication'],
            'mitre': {'technique': [f'T{random.randint(1000,1600)}']}
        },
        'data': {
            'srcip': random.choice(malicious_ips),
            'srcuser': random.choice(['admin', 'root', 'user1'])
        }
    }
    sample_alerts.append(alert)

with open('sample_alerts.json', 'w') as f:
    json.dump(sample_alerts, f, indent=2)

print("✅ Generated 50 sample alerts in sample_alerts.json")