# 🛡️ Phishing Detection API

API backend para detectar ataques de phishing en texto y URLs, diseñado para integrarse con un plugin de navegador Google Chrome.

---

## 📁 Estructura del proyecto

```
phishing_backend/
├── app/
│   ├── api/                # Endpoints de la API
│   ├── core/               # Configuración de entorno
│   ├── db/                 # Conexión y modelos de base de datos
│   ├── models/             # Carga de modelos .pkl
│   ├── schemas/            # Validación con Pydantic
│   └── services/           # Lógica de predicción
├── models/                 # Archivos .pkl del modelo TF-IDF y clasificador
├── .env                    # Variables de entorno
├── create_tables.py        # Script para crear tablas en MySQL
├── requirements.txt        # Dependencias
└── README.md
```

---

## ⚙️ Instalación

1. Clona el repositorio y entra al directorio del proyecto:
```bash
cd phishing_backend
```

2. Crea y activa un entorno virtual:
```bash
python -m venv venv
source venv/bin/activate   # o venv\Scripts\activate en Windows
```

3. Instala dependencias:
```bash
pip install -r requirements.txt
```

4. Configura el archivo `.env`:
```ini
MODEL_DIR=models
ENVIRONMENT=development

MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=*******
MYSQL_DB=phishing_db
```

5. Crea la base de datos si no existe y luego ejecuta:
```bash
python create_tables.py
```

6. Ejecuta el servidor:
```bash
uvicorn app.main:app --reload
```

---

## 🧪 Endpoints disponibles

- `POST /predict_text`
```json
{
  "text": "Verify your PayPal account now."
}
```

- `POST /predict_url`
```json
{
  "url": "http://paypal-verification-login.com"
}
```

Ambos retornan:
```json
{
  "is_phishing": true,
  "confidence": 0.95,
  "message": "Texto clasificado como phishing."
}
```

---

## 🛠️ Modelos requeridos
Ubica los siguientes archivos en `models/`:
- `vectorizer_text.pkl`
- `classifier_text.pkl`
- `vectorizer_url.pkl`
- `classifier_url.pkl`

---

## 📬 Contacto
Desarrollado para fines académicos y de seguridad informática. Para más información, contactar al autor del repositorio.
