# Feature engineering for local processing
# For BigQuery SQL, use the query from the design

import json

def extract_features(normalized_data):
    """Extract features from normalized data for ML training"""
    features = []
    for event in normalized_data:
        feature = {
            'timestamp': event['timestamp'],
            'source': event['source'],
            'event_type': event['event_type'],
            # Add more features based on details
            'feature_1': event['details'].get('some_field', 'default'),
            # Label for supervised learning (need to define logic for malicious/benign)
            'label': 0  # Placeholder: 1 for malicious, 0 for benign
        }
        features.append(feature)
    return features

# Example usage:
# with open('normalized_data.json', 'r') as f:
#     normalized_data = json.load(f)

# training_data = extract_features(normalized_data)
# with open('training_data.json', 'w') as f:
#     json.dump(training_data, f)

# For BigQuery SQL:
# CREATE OR REPLACE TABLE `your-gcp-project-id.security_data.training_data` AS
# SELECT
#     timestamp,
#     source,
#     event_type,
#     JSON_EXTRACT_SCALAR(details, '$.field_name') AS feature_1,
#     CASE
#         WHEN JSON_EXTRACT_SCALAR(details, '$.threat_indicator') = 'malicious' THEN 1
#         ELSE 0
#     END AS label
# FROM
#     `your-gcp-project-id.security_data.events`