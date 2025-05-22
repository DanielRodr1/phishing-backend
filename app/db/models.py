from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy.sql import func
from app.db.connection import Base

class PhishingLog(Base):
    __tablename__ = "phishing_logs"

    id = Column(Integer, primary_key=True, index=True)
    input_type = Column(String(10), nullable=False)  # 'text' o 'url'
    content = Column(String(10000), nullable=False)
    is_phishing = Column(String(5), nullable=False)  # 'True' o 'False'
    confidence = Column(Float, nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())