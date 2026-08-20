FROM python:3.12.8-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 yara-scanner

WORKDIR /opt/fileguard

COPY requirements.txt .
RUN pip install --no-cache-dir --requirement requirements.txt

COPY --chown=yara-scanner:yara-scanner scripts/scan.py ./scan.py

USER yara-scanner

ENTRYPOINT ["python", "/opt/fileguard/scan.py"]
