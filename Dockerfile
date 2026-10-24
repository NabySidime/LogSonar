# LogSonar — image de production
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app/ ./app/
COPY static/ ./static/

# Utilisateur sans privilèges : LogSonar n'a besoin d'aucun droit root.
# L'accès à Docker passe par le proxy de socket en lecture seule.
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin logsonar \
    && mkdir -p /app/data/reports \
    && chown -R logsonar:logsonar /app/data
USER logsonar

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"

# --no-proxy-headers : c'est LogSonar qui décide à quels proxys faire confiance
# (LOGSONAR_TRUSTED_PROXIES), sinon n'importe qui pourrait falsifier son IP.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers", "--no-server-header"]
