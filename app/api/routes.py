from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.schemas.phishing import TextInput, UrlInput, PredictionOutput
from app.services.predictor import predict_text_from_input, predict_url_from_input
from app.db.connection import get_db

router = APIRouter()

@router.post("/predict_text", response_model=PredictionOutput)
def predict_text(input_data: TextInput, db: Session = Depends(get_db)):
    try:
        return predict_text_from_input(input_data.text, db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al predecir texto: {str(e)}")

@router.post("/predict_url", response_model=PredictionOutput)
def predict_url(input_data: UrlInput, db: Session = Depends(get_db)):
    try:
        return predict_url_from_input(input_data.url, db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al predecir URL: {str(e)}")