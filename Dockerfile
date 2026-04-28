FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install -r /app/backend/requirements.txt

COPY backend /app/backend
COPY static /app/static

RUN useradd --system --uid 1000 cipher \
    && mkdir -p /data \
    && chown -R cipher:cipher /data /app

USER cipher

ENV CIPHER_DB=/data/cipher.db \
    CIPHER_STATIC=/app/static \
    CIPHER_TRUST_PROXY=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=4s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health',timeout=3).status==200 else 1)" || exit 1

CMD ["uvicorn", "backend.main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
