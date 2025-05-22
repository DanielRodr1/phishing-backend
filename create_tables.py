from app.db.connection import engine
from app.db.models import Base

if __name__ == "__main__":
    print("📦 Creando tablas en la base de datos...")
    Base.metadata.create_all(bind=engine)
    print("✅ Tablas creadas exitosamente.")