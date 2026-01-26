# Prediction service for ML model
# For Vertex AI deployment:

# from google.cloud import aiplatform

# def deploy_model_and_predict(project_id, model_name, endpoint_display_name, instance):
#     aiplatform.init(project=project_id, location='us-central1')

#     model = aiplatform.Model(model_name=model_name)

#     endpoint = model.deploy(
#         deployed_model_display_name=endpoint_display_name,
#         machine_type='n1-standard-4',
#     )

#     prediction = endpoint.predict(instances=[instance])
#     return prediction

# # Example usage:
# project_id = 'your-gcp-project-id'
# model_name = 'your_model_resource_name' # From the training step
# endpoint_display_name = 'threat_detection_endpoint'

# # Example instance for prediction
# instance = {
#     'feature_1': 'value_1',
#     # ... other features
# }

# prediction = deploy_model_and_predict(project_id, model_name, endpoint_display_name, instance)
# print(f"Prediction: {prediction}")

# For local prediction:
import joblib

def predict_threat(model_path, features):
    """Predict threat using local model"""
    model = joblib.load(model_path)
    prediction = model.predict([features])
    return prediction[0]  # Assuming binary classification

# Example usage:
# threat_score = predict_threat('threat_model.pkl', [0.5])  # feature value
# print(f"Threat prediction: {threat_score}")