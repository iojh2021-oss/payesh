#!/bin/sh
# usage: mldsa-sign.sh KEY.pem FILE OUT_BASE64 [PUBLIC.pem]
# Signs FILE with ML-DSA-65 (FIPS 204) using OpenSSL 3.5+, writes the signature as base64 and verifies it again.
set -e
KEY="$1"; FILE="$2"; OUT="$3"; PUB="$4"
TMP="${TMPDIR:-/tmp}/mldsa.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT
openssl pkey -in "$KEY" -pubout -out "$TMP/pub.pem"
if [ -n "$PUB" ] && [ -f "$PUB" ]; then
  # the secret must belong to the public key committed in the repo
  openssl pkey -pubin -in "$PUB" -outform DER > "$TMP/a.der"
  openssl pkey -pubin -in "$TMP/pub.pem" -outform DER > "$TMP/b.der"
  cmp -s "$TMP/a.der" "$TMP/b.der" || { echo "ERROR: the signing key does not match $PUB"; exit 1; }
fi
for opt in "-rawin" ""; do
  if openssl pkeyutl -sign $opt -inkey "$KEY" -in "$FILE" -out "$TMP/sig.bin" 2>/dev/null &&
     openssl pkeyutl -verify $opt -pubin -inkey "$TMP/pub.pem" -in "$FILE" -sigfile "$TMP/sig.bin" >/dev/null 2>&1; then
    base64 -w0 "$TMP/sig.bin" > "$OUT"
    echo "ML-DSA-65 signature written: $(wc -c < "$TMP/sig.bin") bytes (openssl option: '${opt:-none}')"
    exit 0
  fi
done
echo "ERROR: ML-DSA-65 signing failed (needs OpenSSL 3.5 or newer): $(openssl version)"
exit 1
