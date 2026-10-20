#!/usr/bin/env bash
# One-time setup of the digital signature for the threat database (run in Termux, inside the repo).
#  - generates an ECDSA P-256 key pair
#  - stores the PRIVATE key only as the GitHub secret AV_SIGNING_KEY
#  - writes the PUBLIC key to app/src/main/assets/av-pub.pem ONLY after the secret was saved successfully
set -euo pipefail
REPO="${1:-iojh2021-oss/payesh}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
command -v openssl >/dev/null || { echo "ابتدا نصب کن: pkg install openssl-tool"; exit 1; }
command -v gh >/dev/null || { echo "GitHub CLI (gh) لازم است"; exit 1; }
if [ -n "${GH_TOKEN:-}${GITHUB_TOKEN:-}" ]; then
  echo "هشدار: متغیر GH_TOKEN/GITHUB_TOKEN تنظیم است و ممکن است دسترسی کافی نداشته باشد. اگر خطای 403 دیدی: unset GH_TOKEN GITHUB_TOKEN"
fi
PRIV="$(mktemp)"
PUB="$(mktemp)"
trap 'rm -f "$PRIV" "$PUB"' EXIT
openssl ecparam -name prime256v1 -genkey -noout -out "$PRIV"
openssl ec -in "$PRIV" -pubout -out "$PUB" 2>/dev/null
if ! gh secret set AV_SIGNING_KEY -R "$REPO" < "$PRIV"; then
  echo "ثبت Secret ناموفق بود؛ هیچ فایلی در پروژه تغییر نکرد. وضعیت ورود را ببین: gh auth status"
  exit 1
fi
mkdir -p "$ROOT/app/src/main/assets"
cp "$PUB" "$ROOT/app/src/main/assets/av-pub.pem"
echo "انجام شد: کلید خصوصی فقط در Secret گیت‌هاب (AV_SIGNING_KEY) است و کلید عمومی در app/src/main/assets/av-pub.pem نوشته شد."
echo "حالا: git add . && git commit -m 'Add AV public key' && git push"
