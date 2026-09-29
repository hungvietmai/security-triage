FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl zstd \
    && rm -rf /var/lib/apt/lists/*
COPY experiments/requirements-semgrep.lock.txt /tmp/requirements-semgrep.lock.txt
RUN pip install --no-cache-dir -r /tmp/requirements-semgrep.lock.txt
RUN curl -fL --retry 3 \
      https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.1/codeql-bundle-javascript-linux64.tar.zst \
      -o /tmp/codeql.tar.zst \
    && echo '8d30281899f150633913b08cf4eae755be607f282d643ad418ad638f4210e833  /tmp/codeql.tar.zst' | sha256sum -c - \
    && tar --no-same-owner --zstd -xf /tmp/codeql.tar.zst -C /opt \
    && rm /tmp/codeql.tar.zst
ENV PATH="/opt/codeql:${PATH}" SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0
WORKDIR /app
COPY experiments /app/experiments
ENTRYPOINT ["python", "experiments/run_pilot.py", "--javascript-query-pack", "/opt/codeql/qlpacks/codeql/javascript-queries/2.4.6"]
