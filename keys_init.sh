#!/usr/bin/env bash
set -euo pipefail

# === Config ===
OUT_DIR="${1:-keys}"            # where to put key material
CN="${2:-Offline CMS Recipient}" # certificate subject CN

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

# 1) Generate RSA private key (PKCS#8, encrypted at rest)
#    You will be prompted for a strong passphrase.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  | openssl pkcs8 -topk8 -v2 aes-256-cbc -iter 200000 -passout pass: \
  > "$OUT_DIR/privkey_encrypted.pk8"

# If you prefer to be prompted instead of empty pass: above, do:
#   > "$OUT_DIR/privkey_encrypted.pk8"  # then run: openssl rsa -check -passin stdin …
# But most admins prefer prompt:
#   ... -passout pass:   ← remove and OpenSSL will prompt

# 2) Extract public key for inspection (not used by CMS directly)
openssl pkey -in "$OUT_DIR/privkey_encrypted.pk8" -passin ask -pubout \
  > "$OUT_DIR/pubkey.pem"

# 3) Create a self-signed X.509 certificate for CMS
openssl req -new -x509 -days 3650 -key "$OUT_DIR/privkey_encrypted.pk8" -passin ask \
  -subj "/CN=${CN}" -out "$OUT_DIR/cert.pem"

echo "Wrote:"
echo "  Private key (encrypted PKCS#8): $OUT_DIR/privkey_encrypted.pk8"
echo "  Public key:                     $OUT_DIR/pubkey.pem"
echo "  Certificate (PEM):              $OUT_DIR/cert.pem"
