# Container for the live dashboard (used by the Hugging Face Space; works anywhere Docker runs).
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=7860
RUN useradd -m -u 1000 app
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=app:app . .
USER app

EXPOSE 7860
# --public-demo: visitors can only change synthetic-traffic settings.
CMD ["sh", "-c", "python -m dashboard.server --source synthetic --public-demo --http-host 0.0.0.0 --http-port ${PORT}"]
