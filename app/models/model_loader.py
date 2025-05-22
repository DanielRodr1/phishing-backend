import os
import joblib
from app.core.config import settings

def load_text_model():
    # Ruta del archivo actual (app/models/model_loader.py)
    current_dir = os.path.dirname(os.path.abspath(__file__))

    # Ruta absoluta real hacia la carpeta /models (fuera de /app)
    model_dir = os.path.abspath(os.path.join(current_dir, "../../models"))

    vectorizer_path = os.path.join(model_dir, "tfidf_body.pkl")
    model_path = os.path.join(model_dir, "model_body.pkl")
    scaler_path = os.path.join(model_dir, "scaler.pkl")

    vectorizer = joblib.load(vectorizer_path)
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)

    return vectorizer, model, scaler

def load_url_model():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    model_dir = os.path.abspath(os.path.join(current_dir, "../../models"))

    model_path = os.path.join(model_dir, "classifier_url.pkl")
    return None, joblib.load(model_path)
