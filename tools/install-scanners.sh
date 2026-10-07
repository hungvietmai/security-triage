#!/bin/sh
# Install the pinned Semgrep and CodeQL (tools/pins.env) into a Debian Python image.
# Semgrep goes into the system Python; CodeQL into /opt/codeql. Fails on any mismatch.
set -eu
here=$(dirname "$0")
. "$here/pins.env"

apt-get update
apt-get install -y --no-install-recommends ca-certificates curl zstd
rm -rf /var/lib/apt/lists/*

pip install --no-cache-dir -r "$here/requirements-semgrep.lock.txt"
test "$(SEMGREP_ENABLE_VERSION_CHECK=0 semgrep --version)" = "$SEMGREP_VERSION"

curl -fL --retry 3 "$CODEQL_BUNDLE_URL" -o /tmp/codeql.tar.zst
echo "$CODEQL_BUNDLE_SHA256  /tmp/codeql.tar.zst" | sha256sum -c -
tar --no-same-owner --zstd -xf /tmp/codeql.tar.zst -C /opt
rm /tmp/codeql.tar.zst
test -x /opt/codeql/codeql
test -d "/opt/codeql/qlpacks/codeql/javascript-queries/$CODEQL_JAVASCRIPT_QUERY_PACK"
test -d "/opt/codeql/qlpacks/codeql/python-queries/$CODEQL_PYTHON_QUERY_PACK"
