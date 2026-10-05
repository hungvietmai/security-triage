FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl zstd \
    && rm -rf /var/lib/apt/lists/*

COPY experiments/requirements-semgrep.lock.txt /tmp/requirements-semgrep.lock.txt
RUN pip install --no-cache-dir -r /tmp/requirements-semgrep.lock.txt

RUN curl -fL --retry 3 \
      https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.1/codeql-bundle-linux64.tar.zst \
      -o /tmp/codeql.tar.zst \
    && echo '1ec99cfa9420f04c2330784b4ddb8363a0dd67c3e4471cd93963c50e6c433717  /tmp/codeql.tar.zst' | sha256sum -c - \
    && tar --no-same-owner --zstd -xf /tmp/codeql.tar.zst -C /opt \
    && rm /tmp/codeql.tar.zst \
    && test -x /opt/codeql/codeql \
    && test -d /opt/codeql/qlpacks/codeql/javascript-queries/2.4.6 \
    && test -d /opt/codeql/qlpacks/codeql/python-queries/1.8.11

ENV PATH="/opt/codeql:${PATH}" \
    PYTHONPATH="/app/backend" \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0

WORKDIR /app

COPY backend/app/scanners /app/backend/app/scanners
COPY experiments /app/experiments

ENTRYPOINT ["python", "experiments/run_pilot.py", "--javascript-query-pack", "/opt/codeql/qlpacks/codeql/javascript-queries/2.4.6", "--python-query-pack", "/opt/codeql/qlpacks/codeql/python-queries/1.8.11"]
