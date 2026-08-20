FROM python:3.12.8-slim-bookworm@sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 pdf-scanner \
    && mkdir -p /opt/pdf-tools /output \
    && chown pdf-scanner:pdf-scanner /output

WORKDIR /opt/fileguard

COPY requirements.txt .
RUN pip install --no-cache-dir --requirement requirements.txt

ADD --checksum=sha256:e958a01f1c2596470f27d3c308061b85d7059ff476a58d74f1957a71b4f1248f \
    https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/dea6816048fb2fd3a3597f2e131449fc87f60138/pdfid.py \
    /opt/pdf-tools/pdfid.py

ADD --checksum=sha256:a9fa2faa25e88ab0293543d14aa168ff21fc9fd25a0a8ad657b0dad3171214ac \
    https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/dea6816048fb2fd3a3597f2e131449fc87f60138/pdf-parser.py \
    /opt/pdf-tools/pdf-parser.py

RUN chmod 0444 /opt/pdf-tools/pdfid.py /opt/pdf-tools/pdf-parser.py

COPY --chown=pdf-scanner:pdf-scanner scripts/scan.py ./scan.py

USER pdf-scanner

ENTRYPOINT ["python", "/opt/fileguard/scan.py"]
