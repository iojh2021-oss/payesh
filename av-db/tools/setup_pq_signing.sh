#!/usr/bin/env bash
# ONE-TIME, in Termux, inside the repo. Creates the post-quantum (ML-DSA-65) signing key for the threat database.
#  - private key: only as the GitHub secret AV_MLDSA_KEY
#  - public key:  av-db/pq/av-pub-mldsa65.pem (waits in the repo; NOT yet enforced by the app)
# Needs OpenSSL 3.5+:  pkg upgrade openssl-tool
set -euo pipefail
REPO="${1:-iojh2021-oss/payesh}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
command -v openssl >/dev/null || { echo "pkg install openssl-tool"; exit 1; }
command -v gh >/dev/null || { echo "gh is required"; exit 1; }
openssl list -signature-algorithms 2>/dev/null | grep -qi 'ML-DSA-65' || { echo "This OpenSSL has no ML-DSA ($(openssl version)). Try: pkg upgrade openssl-tool"; exit 1; }
PRIV="$(mktemp)"; PUB="$(mktemp)"; MSG="$(mktemp)"; SIG="$(mktemp)"
trap 'rm -f "$PRIV" "$PUB" "$MSG" "$SIG"' EXIT
openssl genpkey -algorithm ML-DSA-65 -out "$PRIV"
openssl pkey -in "$PRIV" -pubout -out "$PUB"
echo "payesh" > "$MSG"
sh "$ROOT/av-db/tools/mldsa-sign.sh" "$PRIV" "$MSG" "$SIG" "$PUB"   # self-test with the local OpenSSL
if ! gh secret set AV_MLDSA_KEY -R "$REPO" < "$PRIV"; then
  echo "Could not store the secret; nothing in the project was changed. Check: gh auth status"; exit 1
fi
mkdir -p "$ROOT/av-db/pq"
cp "$PUB" "$ROOT/av-db/pq/av-pub-mldsa65.pem"
echo "Done. Private key = GitHub secret AV_MLDSA_KEY. Public key = av-db/pq/av-pub-mldsa65.pem"
echo "Next: git add -A && git commit -m 'ML-DSA public key' && git push, then run the workflow 'Update AV database' once."
