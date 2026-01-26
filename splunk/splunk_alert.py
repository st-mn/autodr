import requests
import json

def create_splunk_alert(splunk_host, splunk_token, alert_details):
    headers = {
        'Authorization': f'Splunk {splunk_token}',
        'Content-Type': 'application/json'
    }
    # This is a simplified example. You might need to use a specific Splunk app or API for alert creation.
    # This example sends the alert to a custom sourcetype.
    response = requests.post(f'https://{splunk_host}:8088/services/collector',
                             headers=headers, data=json.dumps(alert_details), verify=False)
    if response.status_code == 200:
        print("Successfully created alert in Splunk.")
        return True
    else:
        print(f"Failed to create alert in Splunk. Status code: {response.status_code}")
        return False

# Example usage:
# splunk_host = 'your_splunk_host'
# splunk_token = 'your_splunk_hec_token' # Use a HTTP Event Collector token
# alert = {
#     "sourcetype": "ml_threat_detection",
#     "event": {
#         "threat_score": 0.95,
#         "details": "A high-confidence threat was detected.",
#         "source_ip": "192.168.1.100"
#     }
# }
# create_splunk_alert(splunk_host, splunk_token, alert)