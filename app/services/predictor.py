from sqlalchemy.orm import Session
from app.models import model_loader
from app.schemas.phishing import PredictionOutput
from app.db.crud import save_prediction
from app.utils.url_features import extraer_features
from app.utils.text_features import extraer_features_texto
from app.db.models import PhishingLog

# Cargar los modelos desde los archivos .pkl
text_vectorizer, text_model, text_scaler = model_loader.load_text_model()
url_model = model_loader.load_url_model()[1]  # solo modelo, no vectorizador

def predict_text_from_input(text: str, db: Session = None) -> PredictionOutput:
    print("execute predict_text_from_input()")

    if db:
        existing = db.query(PhishingLog).filter_by(input_type="text", content=text).first()
        if existing:
            return PredictionOutput(
                is_phishing=existing.is_phishing.lower() == "true",
                confidence=existing.confidence,
                message="Texto ya evaluado previamente."
            )

    # Extraer features desde función utilitaria
    X_final = extraer_features_texto(text, text_vectorizer, text_scaler)
    print("shape:", X_final.shape)

    prediction = text_model.predict(X_final)[0]
    proba = text_model.predict_proba(X_final)[0][int(prediction)]

    result = PredictionOutput(
        is_phishing=bool(prediction),
        confidence=round(float(proba), 4),
        message="Texto clasificado como phishing." if prediction else "Texto clasificado como seguro."
    )

    if db:
        save_prediction(db, input_type="text", content=text, is_phishing=result.is_phishing, confidence=result.confidence)

    return result

def predict_url_from_input(url: str, db: Session = None) -> PredictionOutput:
    if db:
        existing = db.query(PhishingLog).filter_by(input_type="url", content=url).first()
        if existing:
            return PredictionOutput(
                is_phishing=existing.is_phishing.lower() == "true",
                confidence=existing.confidence,
                message="URL ya evaluada previamente."
            )

    features = extraer_features(url)
    prediction = url_model.predict([features])[0]
    proba = url_model.predict_proba([features])[0][int(prediction)]

    result = PredictionOutput(
        is_phishing=bool(prediction),
        confidence=round(float(proba), 4),
        message="URL clasificada como phishing." if prediction else "URL clasificada como segura."
    )

    if db:
        save_prediction(db, input_type="url", content=url, is_phishing=result.is_phishing, confidence=result.confidence)

    return result