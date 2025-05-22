import os
import joblib
from app.core.config import settings

def get_model_path(filename: str) -> str:
    # Obtiene el path absoluto a /app/models (fuera de /app/app/)
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
    model_dir = os.path.join(project_root, settings.MODEL_DIR)

    full_path = os.path.join(model_dir, filename)
    print("📦 Cargando modelo desde:", full_path)
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