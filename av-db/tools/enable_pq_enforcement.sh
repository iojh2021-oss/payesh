#!/bin/sh
# Run ONLY after the phone test (card "post-quantum" -> "test the database ML-DSA signature") shows a valid signature.
# Bundles the public key into the APK; from then on the app rejects any database update without a valid ML-DSA-65 signature.
set -e
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
[ -f "$ROOT/av-db/pq/av-pub-mldsa65.pem" ] || { echo "run setup_pq_signing.sh first"; exit 1; }
cp "$ROOT/av-db/pq/av-pub-mldsa65.pem" "$ROOT/app/src/main/assets/av-pub-mldsa65.pem"
echo "Done. Now: git add -A && git commit -m 'Enforce ML-DSA database signature' && git push"
