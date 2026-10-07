FROM python:3.12-slim-bookworm

# Pinned Semgrep and CodeQL, shared with backend/Dockerfile.worker (tools/pins.env).
COPY tools /opt/scanner-tools
RUN sh /opt/scanner-tools/install-scanners.sh

ENV PATH="/opt/codeql:${PATH}" \
    PYTHONPATH="/app/backend" \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0

WORKDIR /app

COPY backend/app/scanners /app/backend/app/scanners
COPY backend/app/triage /app/backend/app/triage
COPY experiments /app/experiments

ENTRYPOINT ["python", "experiments/run_pilot.py", "--javascript-query-pack", "/opt/codeql/qlpacks/codeql/javascript-queries/2.4.6", "--python-query-pack", "/opt/codeql/qlpacks/codeql/python-queries/1.8.11"]
