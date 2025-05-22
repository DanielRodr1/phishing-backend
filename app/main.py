from fastapi import FastAPI
from app.api import routes
from app.core.config import settings
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI(title="Phishing Detection API")

# 🛡️ Habilitar CORS para el plugin Chrome
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # en producción puedes especificar: ["chrome-extension://<ID>"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Incluir las rutas de la API
app.include_router(routes.router)

@app.get("/")
async def root():
    return {"message": "API de detección de phishing funcionando", "environment": settings.ENVIRONMENT}
