FROM clamav/clamav:1.4.3

USER root

RUN apk add --no-cache python3

WORKDIR /opt/fileguard

COPY --chown=clamav:clamav scripts/scan.py ./scan.py

USER clamav

ENTRYPOINT ["python3", "/opt/fileguard/scan.py"]
