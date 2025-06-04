from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.schemas.phishing import TextInput, UrlInput, PredictionOutput
from app.services.predictor import predict_text_from_input, predict_url_from_input
from app.db.connection import get_db

router = APIRouter(
    prefix="/predict",
    tags=["Detección de Phishing"],
    responses={404: {"description": "No encontrado"}}
)

@router.post(
    "/text",
    response_model=PredictionOutput,
    summary="Detectar phishing en texto",
    description="""
Evalúa el contenido textual de un correo electrónico para determinar si es un intento de phishing.

- Se puede enviar texto en **español o inglés**.
- El modelo se encargará de seleccionar el modelo lingüístico adecuado automáticamente.
"""
)
def predict_text(input_data: TextInput, db: Session = Depends(get_db)):
    try:
        return predict_text_from_input(input_data.text, db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al predecir texto: {str(e)}")


@router.post(
    "/url",
    response_model=PredictionOutput,
    summary="Detectar phishing en URL",
    description="""
Analiza una URL sospechosa y determina si puede tratarse de una página web fraudulenta.

- Se extraen características estructurales de la URL para su clasificación.
"""
)
def predict_url(input_data: UrlInput, db: Session = Depends(get_db)):
    try:
        return predict_url_from_input(input_data.url, db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al predecir URL: {str(e)}")
