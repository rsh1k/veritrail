# Veritrail service image — slim, non-root, healthchecked.
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the package and metadata, then install it.
COPY pyproject.toml README.md ./
COPY veritrail ./veritrail
RUN pip install --no-cache-dir .

# Run as an unprivileged user (no shell, no home writes needed at runtime).
RUN useradd --system --no-create-home --uid 10001 veritrail
USER veritrail

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else 1)"

CMD ["uvicorn", "veritrail.api.server:app", "--host", "0.0.0.0", "--port", "8080"]
