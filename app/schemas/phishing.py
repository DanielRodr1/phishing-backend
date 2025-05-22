from pydantic import BaseModel

class TextInput(BaseModel):
    text: str

class UrlInput(BaseModel):
    url: str

class PredictionOutput(BaseModel):
    is_phishing: bool
    confidence: float
    message: str