FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY app ./app

# scikit-learn et joblib suffisent à utiliser un modèle : l'extra `ml` sert à l'exploration
RUN pip install --no-cache-dir ".[web,pdf]" scikit-learn joblib

RUN useradd --create-home qrguard
USER qrguard

EXPOSE 8000
CMD ["uvicorn", "qrguard.api:app", "--host", "0.0.0.0", "--port", "8000"]
