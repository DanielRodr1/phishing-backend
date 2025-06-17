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

    # Nuevas columnas para los tiempos
    request_time = Column(DateTime(timezone=True), nullable=False,
                          server_default=func.now())  # Hora en la que se recibe la consulta
    response_time = Column(DateTime(timezone=True), nullable=False,
                           server_default=func.now())  # Hora en la que se da la respuesta