#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $(basename "$0") -r /path/to/recipient_cert.pem -i INPUT -o OUTPUT
Encrypt INPUT into CMS (DER) using AES-256-GCM and RSA recipient.
Options:
  -r  Recipient certificate (PEM, contains RSA public key)
  -i  Input file (to encrypt)
  -o  Output CMS file (e.g., file.cms)
Notes:
  * Uses: openssl cms -encrypt -aes-256-gcm -inform/outform DER
  * Does NOT log secrets. Filenames only.
EOF
}

RECIP=""
IN=""
OUT=""

while getopts ":r:i:o:h" opt; do
  case "$opt" in
    r) RECIP="$OPTARG" ;;
    i) IN="$OPTARG" ;;
    o) OUT="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 1 ;;
  esac
done

[ -n "${RECIP}" ] && [ -f "${RECIP}" ] || { echo "ERR: recipient cert missing"; exit 2; }
[ -n "${IN}" ] && [ -f "${IN}" ] || { echo "ERR: input file missing"; exit 2; }
[ -n "${OUT}" ] || { echo "ERR: output path missing"; exit 2; }

tmp="${OUT}.part"

select_cipher() {
  local list_output

  if list_output=$(openssl list -cipher-algorithms 2>/dev/null); then
    if grep -Eqi 'aes[-_]?256[-_]?gcm' <<<"${list_output}"; then
      return 0
    fi
  fi

  if list_output=$(openssl list-cipher-algorithms 2>/dev/null); then
    if grep -Eqi 'aes[-_]?256[-_]?gcm' <<<"${list_output}"; then
      return 0
    fi
  fi

  return 1
}

CMS_CIPHER=(-aes-256-gcm)
CIPHER_LABEL="AES-256-GCM"
if ! select_cipher; then
  echo "[encrypt] ⚠️ OpenSSL lacks AES-256-GCM support; falling back to AES-256-CBC." >&2
  CMS_CIPHER=(-aes256)
  CIPHER_LABEL="AES-256-CBC"
  echo "[encrypt] ℹ️ Resulting envelope will not provide built-in authentication." >&2
fi

echo "[encrypt] ⏳ Encrypting '${IN}' → '${OUT}' (CMS, ${CIPHER_LABEL})…"

# -binary preserves exact bytes; -stream handles large files with low memory.
openssl cms -encrypt \
  -binary -stream \
  "${CMS_CIPHER[@]}" \
  -in  "${IN}" \
  -out "${tmp}" \
  -outform DER \
  -recip "${RECIP}"

# Atomic move
mv -f -- "${tmp}" "${OUT}"
echo "[encrypt] ✅ Wrote CMS envelope: ${OUT}"
