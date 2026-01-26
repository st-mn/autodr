import requests
import json

def get_wazuh_data(wazuh_api_url, wazuh_user, wazuh_password):
    auth = (wazuh_user, wazuh_password)
    response = requests.get(f'{wazuh_api_url}/agents', auth=auth, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        return None

# Example usage:
# wazuh_api_url = 'https://your_wazuh_api_url:55000'
# wazuh_user = 'your_wazuh_user'
# wazuh_password = 'your_wazuh_password'
# wazuh_data = get_wazuh_data(wazuh_api_url, wazuh_user, wazuh_password)
# if wazuh_data:
#     with open('wazuh_data.json', 'w') as f:
#         json.dump(wazuh_data, f)