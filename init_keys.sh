#!/usr/bin/env bash
set -euo pipefail

# === Config ===
OUT_DIR="${1:-keys}"            # where to put key material
CN="${2:-Offline CMS Recipient}" # certificate subject CN

prompt_passphrase() {
  local pass1 pass2
  while true; do
    read -rsp "Enter passphrase for new private key: " pass1
    echo
    if [[ -z "${pass1}" ]]; then
      echo "Passphrase cannot be empty; please try again." >&2
      continue
    fi

    read -rsp "Confirm passphrase: " pass2
    echo
    if [[ "${pass1}" != "${pass2}" ]]; then
      echo "Passphrases did not match; please try again." >&2
      continue
    fi

    PASSPHRASE="${pass1}"
    return
  done
}

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

prompt_passphrase
export KEYS_INIT_PASSPHRASE="$PASSPHRASE"
trap 'unset -v KEYS_INIT_PASSPHRASE PASSPHRASE' EXIT

# 1) Generate RSA private key (PKCS#8, encrypted at rest)
#    You will be prompted for a strong passphrase.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  | openssl pkcs8 -topk8 -v2 aes-256-cbc -iter 200000 -passout env:KEYS_INIT_PASSPHRASE \
  > "$OUT_DIR/privkey_encrypted.pk8"

# Passphrase collection is handled by prompt_passphrase above. Adjust it if you
# need to automate key generation or source the passphrase differently.

# 2) Extract public key for inspection (not used by CMS directly)
openssl pkey -in "$OUT_DIR/privkey_encrypted.pk8" -passin env:KEYS_INIT_PASSPHRASE -pubout \
  > "$OUT_DIR/pubkey.pem"

# 3) Create a self-signed X.509 certificate for CMS
openssl req -new -x509 -days 3650 -key "$OUT_DIR/privkey_encrypted.pk8" -passin env:KEYS_INIT_PASSPHRASE \
  -subj "/CN=${CN}" -out "$OUT_DIR/cert.pem"

echo "Wrote:"
echo "  Private key (encrypted PKCS#8): $OUT_DIR/privkey_encrypted.pk8"
echo "  Public key:                     $OUT_DIR/pubkey.pem"
echo "  Certificate (PEM):              $OUT_DIR/cert.pem"
echo "  Passphrase:                     $KEYS_INIT_PASSPHRASE"
