from falconpy import api_integrations

def get_crowdstrike_data(client_id, client_secret):
    falcon = api_integrations.APIIntegrations(client_id=client_id, client_secret=client_secret)
    response = falcon.get_combined_plugin_configs()
    if response['status_code'] == 200:
        return response['body']['resources']
    else:
        return None

# Example usage:
# client_id = 'your_crowdstrike_client_id'
# client_secret = 'your_crowdstrike_client_secret'
# crowdstrike_data = get_crowdstrike_data(client_id, client_secret)
# if crowdstrike_data:
#     with open('crowdstrike_data.json', 'w') as f:
#         json.dump(crowdstrike_data, f)