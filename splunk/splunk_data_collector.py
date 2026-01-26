import requests
import json

def get_splunk_data(splunk_host, splunk_token, query):
    headers = {
        'Authorization': f'Splunk {splunk_token}',
    }
    params = {
        'search': f'search {query}',
        'output_mode': 'json',
    }
    response = requests.post(f'https://{splunk_host}:8089/services/search/jobs/export', headers=headers, data=params, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        return None

# Example usage:
# splunk_host = 'your_splunk_host'
# splunk_token = 'your_splunk_token'
# query = 'index=main sourcetype=security_logs'
# splunk_data = get_splunk_data(splunk_host, splunk_token, query)
# if splunk_data:
#     with open('splunk_data.json', 'w') as f:
#         json.dump(splunk_data, f)