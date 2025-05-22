from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    MODEL_DIR: str = "models"
    ENVIRONMENT: str = "development"
    MYSQL_HOST: str = "localhost"
    MYSQL_PORT: int = 3306
    MYSQL_USER: str = "root"
    MYSQL_PASSWORD: str = "sistemas"
    MYSQL_DB: str = "phishing_db"

    class Config:
        env_file = ".env"

@lru_cache()
def get_settings():
    return Settings()

settings = get_settings()