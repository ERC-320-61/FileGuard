FROM python:3.12.8-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 office-scanner

WORKDIR /opt/fileguard

COPY requirements.txt .
RUN pip install --no-cache-dir --requirement requirements.txt

COPY --chown=office-scanner:office-scanner scripts/scan.py ./scan.py

USER office-scanner

ENTRYPOINT ["python", "/opt/fileguard/scan.py"]
