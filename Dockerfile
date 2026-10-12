# =============================================================================
# ExplainPhish Autonomous SOC Workstation — Production Dockerfile
# Multi-stage security container for document triage & ML ensemble inference
# =============================================================================

FROM python:3.13-slim

# Set environment flags:
# - PYTHONUNBUFFERED: Real-time stdout/stderr logging
# - PYTHONDONTWRITEBYTECODE: Prevents .pyc file generation
# - PORT: Default listening port
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080 \
    PYTHONPATH="/app:/app/InterfaceExplainPhish"

# Install system dependencies:
# - libgomp1: Required by OpenMP for XGBoost and LightGBM parallel inference
# - curl: Used by Docker HEALTHCHECK probe
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root application user for defense-in-depth isolation
RUN groupadd -g 1000 appuser && \
    useradd -u 1000 -g appuser -m -s /bin/bash appuser

WORKDIR /app

# Install Python dependencies first to leverage Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code, models, and test suite
COPY InterfaceExplainPhish/ ./InterfaceExplainPhish/
COPY models/ ./models/
COPY tests/ ./tests/
COPY pyrightconfig.json .

# Create persistence directories and assign permissions to unprivileged user
RUN mkdir -p /app/InterfaceExplainPhish/downloads \
             /app/InterfaceExplainPhish/reports && \
    chown -R appuser:appuser /app

# Switch to non-root execution context
USER appuser

# Expose web console and REST API port
EXPOSE 8080

# Production Healthcheck Probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT}/api/health || exit 1

# Launch ExplainPhish High-Performance Web Workstation
CMD ["uvicorn", "web_app:app", "--app-dir", "InterfaceExplainPhish", "--host", "0.0.0.0", "--port", "8080"]
