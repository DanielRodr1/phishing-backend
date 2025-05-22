from sqlalchemy.orm import Session
from app.db.models import PhishingLog

def save_prediction(db: Session, input_type: str, content: str, is_phishing: bool, confidence: float):
    log = PhishingLog(
        input_type=input_type,
        content=content,
        is_phishing=str(is_phishing),
        confidence=confidence
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log