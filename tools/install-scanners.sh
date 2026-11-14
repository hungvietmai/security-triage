#!/bin/sh
# Install the pinned scanners (tools/pins.env) into a Debian Python image. Fails on any
# mismatch. Semgrep goes into the system Python and CodeQL into /opt/codeql. Bandit gets its
# own virtual environment so its dependencies cannot disturb Semgrep's. ESLint is installed
# next to its pinned configuration in tools/eslint, on a pinned Node.js in /opt/node that is
# also put on PATH for CodeQL.
set -eu
here=$(dirname "$0")
. "$here/pins.env"

apt-get update
apt-get install -y --no-install-recommends ca-certificates curl xz-utils zstd
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

python -m venv /opt/bandit
/opt/bandit/bin/pip install --no-cache-dir -r "$here/requirements-bandit.lock.txt"
ln -s /opt/bandit/bin/bandit /usr/local/bin/bandit
test "$(bandit --version | head -n 1)" = "bandit $BANDIT_VERSION"

curl -fL --retry 3 "$NODE_TARBALL_URL" -o /tmp/node.tar.xz
echo "$NODE_TARBALL_SHA256  /tmp/node.tar.xz" | sha256sum -c -
mkdir /opt/node
tar --no-same-owner -xJf /tmp/node.tar.xz -C /opt/node --strip-components=1
rm /tmp/node.tar.xz
test "$(/opt/node/bin/node --version)" = "v$NODE_VERSION"
# CodeQL's JavaScript extractor starts "node" from PATH to parse TypeScript; without it,
# database creation fails for any source tree that contains a .ts file.
ln -s /opt/node/bin/node /usr/local/bin/node
# npm ci installs exactly package-lock.json; --ignore-scripts runs no package install script.
(cd "$here/eslint" && PATH="/opt/node/bin:$PATH" npm ci --ignore-scripts --no-audit --no-fund)
rm -rf /root/.npm
eslint_root=$(cd "$here/eslint" && pwd)
printf '#!/bin/sh\nexec /opt/node/bin/node %s/node_modules/eslint/bin/eslint.js "$@"\n' "$eslint_root" \
  > /usr/local/bin/eslint
chmod 755 /usr/local/bin/eslint
test "$(eslint --version)" = "v$ESLINT_VERSION"
test -f "$eslint_root/node_modules/@microsoft/eslint-formatter-sarif/sarif.js"
