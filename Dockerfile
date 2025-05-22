# Dockerfile para FastAPI Phishing Detection API
FROM python:3.10-slim

# Crear directorio de trabajo
WORKDIR /app

# Copiar dependencias
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código fuente
COPY . .

# Puerto expuesto por Uvicorn
EXPOSE 8000

# Comando de inicio
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
