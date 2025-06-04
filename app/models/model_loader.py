import joblib
import os

def load_text_model(lang='en'):

    if lang not in ['en', 'es']:
        raise ValueError("Idioma no soportado: use 'en' o 'es'.")

    base_dir = os.path.dirname(os.path.abspath(__file__))
    lang_dir = os.path.join(base_dir, lang)

    vectorizer = joblib.load(os.path.join(lang_dir, "tfidf_body.pkl"))
    model = joblib.load(os.path.join(lang_dir, "model_body.pkl"))
    scaler = joblib.load(os.path.join(lang_dir, "scaler.pkl"))

    return vectorizer, model, scaler

def load_url_model():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    model = joblib.load(os.path.join(current_dir, "classifier_url.pkl"))
    return None, model
