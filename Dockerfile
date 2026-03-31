# ── Stage 1: Builder ─────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: Runtime ─────────────────────────────────
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Non-root user for security (cache early)
RUN addgroup --system appgroup && \
    adduser --system --ingroup appgroup appuser

# Copy only installed packages from builder
COPY --from=builder /install /usr/local

# Create data directory for cache and XML downloads
RUN mkdir -p /app/data && \
    chown -R appuser:appgroup /app/data

# Copy application code (this changes frequently; placing it near the end maximizes caching)
COPY --chown=appuser:appgroup app/ ./app/

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=5 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/api/health').raise_for_status()" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
