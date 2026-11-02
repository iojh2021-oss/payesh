#!/bin/sh
# Run ONCE in Termux. Creates a permanent signing key for the Payesh APK and stores it in the GitHub secrets,
# so every later build can be installed OVER the previous one (settings, app lock and learned data stay).
# Needs: pkg install openjdk-17 gh   and   gh auth login
set -e
R=iojh2021-oss/payesh
KS="$HOME/payesh.keystore"
[ -f "$KS" ] && { echo "$KS already exists: not overwriting it. Delete it only if you really want a NEW identity."; exit 1; }
command -v keytool >/dev/null || { echo "keytool missing: pkg install openjdk-17"; exit 1; }
PW=$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)
keytool -genkeypair -keystore "$KS" -alias payesh -keyalg RSA -keysize 4096 -validity 36500 \
  -storepass "$PW" -keypass "$PW" -dname "CN=Payesh"
base64 -w0 "$KS" | gh secret set KEYSTORE_BASE64 -R "$R"
printf '%s' "$PW" | gh secret set KEYSTORE_PASSWORD -R "$R"
printf '%s\n' "$PW" > "$KS.password"
chmod 600 "$KS" "$KS.password"
echo
echo "Done. Back up these two files somewhere safe (NOT in the repo):"
echo "  $KS"
echo "  $KS.password"
echo "If they are lost, the next build gets a new identity and you must uninstall the old app once more."
