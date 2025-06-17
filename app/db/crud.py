from datetime import datetime
from sqlalchemy.orm import Session
from app.db.models import PhishingLog

def save_prediction(db: Session, input_type: str, content: str, is_phishing: bool, confidence: float, request_time: datetime, response_time: datetime):
    log = PhishingLog(
        input_type=input_type,
        content=content,
        is_phishing=str(is_phishing),
        confidence=confidence,
        request_time=request_time,
        response_time=response_time
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log