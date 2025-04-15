import joblib

# Load model at startup
model = joblib.load('models/phishing_model.pkl')
vectorizer = joblib.load('models/vectorizer.pkl')

def predict_phishing(email_text):
    # Transform the email text to vectorized form
    email_vector = vectorizer.transform([email_text])
    
    # Make prediction
    prediction = model.predict(email_vector)

    # Print the result
    return prediction[0]

