FROM python:3.12.14-slim-trixie@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install --no-install-recommends -y libmagic1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 classifier

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --requirement requirements.txt

COPY --chown=classifier:classifier src/classifier.py .

USER classifier

ENTRYPOINT ["python", "/app/classifier.py"]
