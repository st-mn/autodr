# Main pipeline script to orchestrate the data collection, processing, and ML
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from splunk.splunk_data_collector import get_splunk_data
from crowdstrike.crowdstrike_data_collector import get_crowdstrike_data
from wazuh.wazuh_data_collector import get_wazuh_data
from data.data_normalizer import normalize_data
from data.data_loader import load_to_local_storage
from vertex.feature_engineering import extract_features
from vertex.ml_model import train_local_model
from vertex.ml_predictor import predict_threat

def run_pipeline():
    # Configuration - replace with actual values
    splunk_host = 'your_splunk_host'
    splunk_token = 'your_splunk_token'
    query = 'index=main sourcetype=security_logs'
    
    client_id = 'your_crowdstrike_client_id'
    client_secret = 'your_crowdstrike_client_secret'
    
    wazuh_api_url = 'https://your_wazuh_api_url:55000'
    wazuh_user = 'your_wazuh_user'
    wazuh_password = 'your_wazuh_password'
    
    # Data collection
    print("Collecting data...")
    splunk_data = get_splunk_data(splunk_host, splunk_token, query)
    crowdstrike_data = get_crowdstrike_data(client_id, client_secret)
    wazuh_data = get_wazuh_data(wazuh_api_url, wazuh_user, wazuh_password)
    
    # Normalization
    print("Normalizing data...")
    normalized_data = normalize_data(splunk_data, crowdstrike_data, wazuh_data)
    
    # Storage
    print("Storing data...")
    load_to_local_storage(normalized_data)
    
    # Feature engineering
    print("Extracting features...")
    training_data = extract_features(normalized_data)
    with open('training_data.json', 'w') as f:
        json.dump(training_data, f)
    
    # Train model (if needed)
    print("Training model...")
    model = train_local_model('training_data.json')
    
    # Example prediction
    print("Making prediction...")
    threat_score = predict_threat('threat_model.pkl', [0.5])  # Example feature
    print(f"Threat score: {threat_score}")
    
    # If threat detected, trigger responses
    if threat_score == 1:
        print("Threat detected! Triggering automated responses...")
        # Call response functions here

if __name__ == "__main__":
    run_pipeline()