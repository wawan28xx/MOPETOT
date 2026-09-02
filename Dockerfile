FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
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
    && groupadd --system mopenot \
    && useradd --system --gid mopenot --home-dir /app mopenot

COPY web/requirements.txt /tmp/requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r /tmp/requirements.txt

COPY --chown=mopenot:mopenot . .

RUN mkdir -p web/uploads web/results web/database \
    && chown -R mopenot:mopenot web/uploads web/results web/database \
    && if [ -f bin/jadx/bin/jadx ]; then \
        chmod +x bin/jadx/bin/jadx; \
        rm -f bin/jadx/bin/jadx.bat; \
        ln -s jadx bin/jadx/bin/jadx.bat; \
    fi

USER mopenot

EXPOSE 8089

VOLUME ["/app/web/uploads", "/app/web/results", "/app/web/database"]

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8089/api/scans?per_page=5', timeout=3)"]

STOPSIGNAL SIGTERM

CMD ["python", "-m", "uvicorn", "app:app", "--app-dir", "web", "--host", "0.0.0.0", "--port", "8089"]
