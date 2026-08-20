FROM python:3.12.8-slim-bookworm@sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    XDG_CACHE_HOME=/tmp/capa-cache

RUN useradd --create-home --uid 10001 capa-scanner

WORKDIR /opt/fileguard

COPY requirements.txt .
RUN pip install --no-cache-dir --requirement requirements.txt

ADD --checksum=sha256:273591b11737181b3bdaac18964f23627cf10c21c2b143fc9be88e4a33217669 \
    https://github.com/mandiant/capa-rules/archive/refs/tags/v9.4.0.tar.gz \
    /tmp/capa-rules.tar.gz

ADD --checksum=sha256:562edd9617b23286e74d06f0115d99217a4df178e43925375af0c35d5cae8d66 \
    https://github.com/mandiant/capa/archive/refs/tags/v9.4.0.tar.gz \
    /tmp/capa-source.tar.gz

RUN mkdir /opt/capa-rules \
    && tar --extract --gzip --file /tmp/capa-rules.tar.gz \
        --directory /opt/capa-rules --strip-components=1 \
    && mkdir /tmp/capa-source /opt/capa-sigs \
    && tar --extract --gzip --file /tmp/capa-source.tar.gz \
        --directory /tmp/capa-source --strip-components=1 \
    && cp -R /tmp/capa-source/sigs/. /opt/capa-sigs/ \
    && rm -rf /tmp/capa-rules.tar.gz /tmp/capa-source.tar.gz /tmp/capa-source

COPY --chown=capa-scanner:capa-scanner scripts/scan.py ./scan.py

USER capa-scanner

ENTRYPOINT ["python", "/opt/fileguard/scan.py"]
