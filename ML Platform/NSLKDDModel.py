import joblib
import pandas as pd


class NSLKDDModel:
    def __init__(self, model_path='models/nsl_kdd_model.pkl'):
        self.model = joblib.load(model_path)
        self.class_names = {0: 'normal', 1: 'anomaly'}

    
    def predict(self, input_data):
        if isinstance(input_data, dict):
            input_df = pd.DataFrame([input_data])
        else:
            input_df = input_data.copy()
        try:
            pred = self.model.predict(input_df)[0]
            proba = self.model.predict_proba(input_df)
            if proba.shape[1] == 1:
                normal_prob = float(proba[0, 0]) if pred == 0 else 1 - float(proba[0, 0])
                anomaly_prob = 1 - normal_prob
            else:
                normal_prob = float(proba[0, 0])
                anomaly_prob = float(proba[0, 1])
            return {
                'prediction': self.class_names[pred],
                'probability': max(normal_prob, anomaly_prob),
                'details': {
                    'normal_probability': normal_prob,
                    'anomaly_probability': anomaly_prob
                }
            }
        except Exception as e:
            return {
                'error': str(e),
                'input_features': list(input_df.columns),
                'input_values': input_df.iloc[0].to_dict()
            }
        
# Load model once
model = NSLKDDModel()


def predictLine(protocol,service,duration,flag,src_bytes,dst_bytes,land,wrong_fragment,urgent):
    sample_input = {
        'protocol_type': protocol,
        'src_bytes': src_bytes,               
        'dst_bytes': dst_bytes,
        'duration': duration,                
        'flag': flag,
        'land': land,
        'wrong_fragment': wrong_fragment,
        'urgent': urgent,
        'service': service
    }
    
    # Make prediction
    result = model.predict(sample_input)
    return result
