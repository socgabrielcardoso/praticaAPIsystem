FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN addgroup --system app && adduser --system --ingroup app app

COPY pyproject.toml LICENSE ./
COPY src ./src

RUN pip install --upgrade pip && pip install .

USER app

EXPOSE 8080

CMD ["uvicorn", "pratica_api_system.api:app", "--host", "0.0.0.0", "--port", "8080"]
