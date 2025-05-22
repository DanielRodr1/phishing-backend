import os
import joblib
from app.core.config import settings

def load_text_model():
    vectorizer_path = os.path.join(settings.MODEL_DIR, "tfidf_body.pkl")
    model_path = os.path.join(settings.MODEL_DIR, "model_body.pkl")
    scaler_path = os.path.join(settings.MODEL_DIR, "scaler.pkl")

    vectorizer = joblib.load(vectorizer_path)
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)

    return vectorizer, model, scaler

def load_url_model():
    model_path = os.path.join(settings.MODEL_DIR, "classifier_url.pkl")
    model = joblib.load(model_path)
    return None, model
