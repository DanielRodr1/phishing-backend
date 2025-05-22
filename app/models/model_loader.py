import os
import joblib
from app.core.config import settings

def get_model_path(filename: str) -> str:
    """
    Retorna la ruta absoluta del archivo de modelo.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # /app/
    model_dir = os.path.join(base_dir, settings.MODEL_DIR)
    full_path = os.path.join(model_dir, filename)

    print("📦 Intentando cargar:", full_path)  # Esto aparecerá en Railway Logs
    return full_path

def load_text_model():
    vectorizer_path = get_model_path("tfidf_body.pkl")
    model_path = get_model_path("model_body.pkl")
    scaler_path = get_model_path("scaler.pkl")

    vectorizer = joblib.load(vectorizer_path)
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)

    return vectorizer, model, scaler

def load_url_model():
    model_path = get_model_path("classifier_url.pkl")
    model = joblib.load(model_path)
    return None, model