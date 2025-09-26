#!/usr/bin/env bash
set -euo pipefail

# === Config ===
OUT_DIR="${1:-keys}"            # where to put key material
LABEL="${2:-SFD PQC Recipient}" # informational label stored with the public key

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

node "$(dirname "$0")/tools/generate_pq_keys.js" "$OUT_DIR" "$LABEL"

echo "Wrote:"
echo "  Public key:                     $OUT_DIR/public_key.json"
echo "  Private key (encrypted JSON):   $OUT_DIR/private_key_encrypted.json"
echo "  Passphrase:                     $KEYS_INIT_PASSPHRASE"
