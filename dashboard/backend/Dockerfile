FROM python:3.11-slim

# Variables d'environnement
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Installation des dépendances système
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    curl \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Mise à jour de pip
RUN pip install --upgrade pip

# Création du répertoire de travail principal
WORKDIR /app

# Copie du fichier requirements.txt depuis le contexte de build
COPY dashboard/backend/requirements.txt /app/dashboard/backend/requirements.txt

RUN pip install --no-cache-dir --retries 3 --timeout 60 -r /app/dashboard/backend/requirements.txt || \
    (echo "❌ Erreur installation requirements, installation manuelle..." && \
     pip install flask flask-socketio flask-cors psycopg2-binary redis asyncpg reportlab jinja2 python-dateutil matplotlib seaborn)

RUN pip install --no-cache-dir \
    psutil \
    reportlab \
    jinja2 \
    asyncpg \
    python-dateutil \
    matplotlib \
    seaborn \
    pillow
# Installation des dépendances Python avec retry
RUN pip install --no-cache-dir --retries 3 --timeout 30 -r /app/dashboard/backend/requirements.txt
RUN pip install psutil
# Copie de tout le code source
COPY . /app/


# Définition du répertoire de travail final
WORKDIR /app/dashboard/backend

# Création des répertoires nécessaires
RUN mkdir -p /app/logs /app/static /app/templates /app/reports && \
    chmod 755 /app/logs /app/static /app/templates /app/reports
# Test de santé
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Port d'exposition
EXPOSE 5000

# Vérification de la structure (debug)
RUN echo "=== Structure projet ===" && \
    ls -la /app/ && \
    echo "=== Scripts disponibles ===" && \
    ls -la /app/scripts/ 2>/dev/null || echo "Scripts manquant!" && \
    echo "=== Dashboard backend ===" && \
    ls -la /app/dashboard/backend/ && \
    echo "=== Test Flask ===" && \
    python -c "import flask; print('Flask version:', flask.__version__)" || echo "Flask import failed!" && \
    echo "=== Packages installés ===" && \
    pip list | head -20

# Commande par défaut
CMD ["python", "app.py"]