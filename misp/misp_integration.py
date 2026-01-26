from pymisp import PyMISP

def add_ioc_to_misp(misp_url, misp_key, event_id, ioc_value, ioc_type):
    misp = PyMISP(misp_url, misp_key, ssl=False)
    event = misp.get_event(event_id)
    if event:
        misp.add_attribute(event, {'type': ioc_type, 'value': ioc_value})
        print(f"Successfully added IOC {ioc_value} to MISP event {event_id}")
        return True
    else:
        print(f"Failed to find MISP event {event_id}")
        return False

# Example usage:
# misp_url = 'https://your_misp_instance'
# misp_key = 'your_misp_api_key'
# event_id = 'event_id_to_update' # The MISP event to add the IOC to
# ioc_value = 'malicious-domain.com'
# ioc_type = 'domain'
# add_ioc_to_misp(misp_url, misp_key, event_id, ioc_value, ioc_type)