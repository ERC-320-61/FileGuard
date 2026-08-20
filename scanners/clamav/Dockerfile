FROM clamav/clamav:1.4.3@sha256:75fb5fd95fcbe1d7e6d240c369c1572b686ee2c95949d1042b5148de8eddebb4

USER root

RUN apk add --no-cache python3

WORKDIR /opt/fileguard

COPY --chown=clamav:clamav scripts/scan.py ./scan.py

USER clamav

ENTRYPOINT ["python3", "/opt/fileguard/scan.py"]
