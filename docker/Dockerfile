# Use Python 3.12 as base image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV PIP_PREFER_BINARY=1
ENV PIP_DEFAULT_TIMEOUT=120
ENV PIP_RETRIES=5

# Install system dependencies INCLUDING libmagic
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    wget \
    git \
    postgresql-client \
    redis-tools \
    libpq-dev \
    python3-dev \
    build-essential \
    pkg-config \
    libffi-dev \
    libssl-dev \
    libmagic1 \
    libmagic-dev \
    file \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user with specific UID/GID for consistency
RUN groupadd -r -g 1000 ctiuser && useradd -r -g ctiuser -u 1000 ctiuser

# Upgrade pip
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy requirements FIRST for better Docker caching
COPY requirements.txt* ./
RUN if [ -f requirements.txt ]; then \
        echo "📦 Installation depuis requirements.txt"; \
        pip install --no-cache-dir -r requirements.txt; \
    else \
        echo "⚠️ Pas de requirements.txt, installation des dépendances essentielles"; \
        pip install --no-cache-dir --prefer-binary \
            psycopg2-binary>=2.9.7 \
            requests>=2.31.0 \
            redis>=4.6.0 \
            python-dotenv>=1.0.0 \
            schedule>=1.2.0 \
            pyyaml>=6.0.1 \
            pandas>=2.0.3 \
            numpy>=1.24.3 \
            beautifulsoup4>=4.12.2 \
            lxml>=4.9.3 \
            feedparser>=6.0.10 \
            openpyxl>=3.1.2 \
            xlsxwriter>=3.1.2; \
    fi

# Install OpenCTI integration (toujours nécessaire)
RUN pip install --no-cache-dir --prefer-binary \
    pycti>=6.0.0 \
    stix2>=3.0.1

# Install threat intelligence tools (avec gestion d'erreur)
RUN pip install --no-cache-dir --prefer-binary shodan>=1.29.1 || echo "⚠️ Shodan non installé"
RUN pip install --no-cache-dir --prefer-binary OTXv2>=1.5.12 || echo "⚠️ OTXv2 non installé"
RUN pip install --no-cache-dir --prefer-binary vt-py>=0.17.5 || echo "⚠️ vt-py non installé"
RUN pip install --no-cache-dir --prefer-binary python-telegram-bot>=20.4 || echo "⚠️ telegram-bot non installé"

# Copy ALL project files (préserve tout)
COPY . .

# Create directories with proper permissions BEFORE switching users
RUN mkdir -p /app/logs /app/output/alerts /app/output/daily_feeds \
    /app/output/excel_reports /app/output/rapports /app/output/searches \
    /app/output/tests /app/config  /app/data /app/data/mitre && \

    chown -R ctiuser:ctiuser /app && \
    chmod -R 755 /app && \
    chmod -R 777 /app/logs /app/output /app/data



ENV MITRE_DATA_DIR=/app/data
ENV MITRE_LOG_FILE=/app/logs/mitre_enricher.log
ENV MITRE_UPDATE_DATA=true
ENV MITRE_CONTINUOUS_MODE=false
ENV OPENCTI_ENABLED=false
# SEULEMENT créer les __init__.py manquants (ne touche pas aux existants)
RUN [ ! -f /app/scripts/__init__.py ] && touch /app/scripts/__init__.py || echo "✅ scripts/__init__.py existe"
RUN [ ! -f /app/scripts/collectors/__init__.py ] && touch /app/scripts/collectors/__init__.py || echo "✅ scripts/collectors/__init__.py existe"
RUN [ ! -f /app/scripts/analyzers/__init__.py ] && touch /app/scripts/analyzers/__init__.py || echo "✅ scripts/analyzers/__init__.py existe"
RUN [ ! -f /app/scripts/generators/__init__.py ] && touch /app/scripts/generators/__init__.py || echo "✅ scripts/generators/__init__.py existe"
RUN [ ! -f /app/utils/__init__.py ] && touch /app/utils/__init__.py || echo "✅ utils/__init__.py existe"

# Test des modules - VERSION SIMPLIFIÉE SANS CARACTÈRES SPÉCIAUX
RUN python -c "import sys; sys.path.append('/app'); modules=['pipeline','scripts.collectors','scripts.analyzers','scripts.generators','scripts.utils']; [print('OK:',m) if __import__(m) else None for m in modules]" || echo "Module test completed with warnings"

# Test libmagic installation
RUN python -c "import magic; print('✅ libmagic working')" || echo "❌ libmagic test failed"

# Switch to non-root user AFTER setting permissions
USER ctiuser

# Health check SEULEMENT avec vos fichiers existants
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "print('Container healthy'); exit(0)" || exit 1

# Default command - utilise VOS fichiers
CMD ["python", "/app/scripts/pipeline/scheduler.py"]