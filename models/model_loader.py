import joblib
import os

def load_text_model():
    current_dir = os.path.dirname(os.path.abspath(__file__))

    vectorizer = joblib.load(os.path.join(current_dir, "tfidf_body.pkl"))
    model = joblib.load(os.path.join(current_dir, "model_body.pkl"))
    scaler = joblib.load(os.path.join(current_dir, "scaler.pkl"))

    return vectorizer, model, scaler

def load_url_model():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    model = joblib.load(os.path.join(current_dir, "classifier_url.pkl"))
    return None, model
