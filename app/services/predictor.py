from datetime import datetime
from sqlalchemy.orm import Session
from app.models import model_loader
from app.schemas.phishing import PredictionOutput
from app.db.crud import save_prediction
from app.utils.language import detect_language
from app.utils.url_features import extraer_features
from app.utils.text_features import extraer_features_texto
from app.db.models import PhishingLog

# Cargar los modelos desde los archivos .pkl
url_model = model_loader.load_url_model()[1]  # solo modelo, no vectorizador

def predict_text_from_input(text: str, db: Session = None) -> PredictionOutput:
    print("execute predict_text_from_input()")
    start_time = datetime.now()

    lang = detect_language(text)
    print(f"Idioma detectado: {lang}")

    if db:
        db_start = datetime.now()
        existing = db.query(PhishingLog).filter_by(input_type="text", content=text).first()
        db_elapsed = datetime.now() - db_start
        if existing:
            return PredictionOutput(
                is_phishing=True if existing.is_phishing.lower() == "true" else False,
                confidence=float(existing.confidence),
                message=f"Texto ya evaluado previamente (idioma: {lang}).",
                inference_time=str(db_elapsed)
            )

    vectorizer, model, scaler = model_loader.load_text_model(lang)
    X_final = extraer_features_texto(text, vectorizer, scaler)
    print("Shape:", X_final.shape)

    prediction = model.predict(X_final)[0]
    proba = model.predict_proba(X_final)[0][int(prediction)]

    end_time = datetime.now()
    inference_time = end_time - start_time
    inference_time_str = str(inference_time)
    print(f"Tiempo de inferencia para texto: {inference_time_str}")

    result = PredictionOutput(
        is_phishing=bool(prediction),
        confidence=round(float(proba), 4),
        message=f"Texto clasificado como {'phishing' if prediction else 'seguro'} (idioma detectado: {lang}).",
        inference_time=inference_time_str
    )

    if db:
        save_prediction(
            db,
            input_type="text",
            content=text,
            is_phishing=result.is_phishing,
            confidence=result.confidence,
            request_time=start_time,
            response_time=end_time
        )

    return result

def predict_url_from_input(url: str, db: Session = None) -> PredictionOutput:
    start_time = datetime.now()
    print("⏱️  Entré a predict_url_from_input")
    if db:
        print("🔍  Consultando BD…")
        db_start = datetime.now()
        existing = db.query(PhishingLog).filter_by(input_type="url", content=url).first()
        db_elapsed = datetime.now() - db_start
        if existing:
            return PredictionOutput(
                is_phishing=True if existing.is_phishing.lower() == "true" else False,
                confidence=float(existing.confidence),
                message="URL ya evaluada previamente.",
                inference_time=str(db_elapsed)
            )
    print("Extrayendo features")
    features = extraer_features(url)
    print("Llamando a model.predict")
    prediction = url_model.predict([features])[0]
    print("Model.predict devolvió resultado")
    proba = url_model.predict_proba([features])[0][int(prediction)]

    end_time = datetime.now()
    inference_time = end_time - start_time
    inference_time_str = str(inference_time)
    print(f"Tiempo de inferencia para URL: {inference_time_str}")

    result = PredictionOutput(
        is_phishing=bool(prediction),
        confidence=round(float(proba), 4),
        message="URL clasificada como phishing." if prediction else "URL clasificada como segura.",
        inference_time=inference_time_str
    )

    if db:
        print("Guardando log en BD")
        save_prediction(
            db,
            input_type="url",
            content=url,
            is_phishing=result.is_phishing,
            confidence=result.confidence,
            request_time=start_time,
            response_time=end_time
        )
        print("Log guardado")

    print("Resultado que se retornará:", result)

    return result