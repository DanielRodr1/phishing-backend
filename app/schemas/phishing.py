from typing import Optional

from pydantic import BaseModel, Field

class TextInput(BaseModel):
    text: str = Field(..., example="Estimado cliente, hemos detectado actividad sospechosa. Inicie sesión para verificar su cuenta.")

class UrlInput(BaseModel):
    url: str = Field(..., example="http://secure-banco.com/verify-login")

class PredictionOutput(BaseModel):
    is_phishing: bool = Field(..., description="True si el contenido es phishing.")
    confidence: float = Field(..., description="Nivel de confianza del modelo en la predicción.")
    message: str = Field(..., description="Explicación legible del resultado.")
    inference_time: Optional[str] = Field(default=None, description="Tiempo de inferencia de la predicción.")
