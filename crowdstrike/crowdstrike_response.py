# Automated response integrations
# As per the design

from falconpy import hosts

def isolate_host(client_id, client_secret, agent_id, comment):
    falcon = hosts.Hosts(client_id=client_id, client_secret=client_secret)
    response = falcon.perform_action(ids=[agent_id], action_name='contain', comment=comment)
    if response['status_code'] == 202:
        print(f"Successfully initiated isolation for agent {agent_id}")
        return True
    else:
        print(f"Failed to isolate agent {agent_id}. Error: {response['body']['errors']}")
        return False

# Example usage:
# client_id = 'your_crowdstrike_client_id'
# client_secret = 'your_crowdstrike_client_secret'
# agent_id_to_isolate = 'agent_id_from_event'
# comment = 'High-confidence threat detected by ML model.'
# isolate_host(client_id, client_secret, agent_id_to_isolate, comment)