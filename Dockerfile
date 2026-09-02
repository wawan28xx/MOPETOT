FROM python:3.13-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    MOPETOT_UPLOAD_DIR=/data/uploads \
    MOPETOT_RESULTS_DIR=/data/results \
    MOPETOT_DB_PATH=/data/database/mobile_audit.db \
    MOPETOT_MAX_UPLOAD_BYTES=524288000 \
    MOPETOT_MAX_CONCURRENT_SCANS=1 \
    MOPETOT_RETENTION_DAYS=30 \
    JAVA_HOME=/usr/lib/jvm/default-java \
    PATH="/usr/lib/jvm/default-java/bin:${PATH}"

WORKDIR /app

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        binutils \
        default-jre-headless \
        file \
        unzip \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 mopenot \
    && useradd --uid 10001 --gid mopenot --home-dir /app --no-create-home mopenot

COPY web/requirements.txt /tmp/requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r /tmp/requirements.txt

COPY --chown=mopenot:mopenot . .

RUN mkdir -p /data/uploads /data/results /data/database \
    && chown -R mopenot:mopenot /data \
    && if [ -f bin/jadx/bin/jadx ]; then \
        chmod +x bin/jadx/bin/jadx; \
        rm -f bin/jadx/bin/jadx.bat; \
        ln -s jadx bin/jadx/bin/jadx.bat; \
    fi \
    && python -m compileall -q \
        mobile_audit.py apkid_wrapper.py secret_scanner.py engines web

USER mopenot

EXPOSE 8089

VOLUME ["/data"]

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8089/healthz', timeout=3)"]

STOPSIGNAL SIGTERM

CMD ["python", "-m", "uvicorn", "app:app", "--app-dir", "web", "--host", "0.0.0.0", "--port", "8089", "--proxy-headers", "--forwarded-allow-ips=*"]

FROM base AS runtime
