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
echo "[encrypt] ⏳ Encrypting '${IN}' → '${OUT}' (CMS, AES-256-GCM)…"

# -binary preserves exact bytes; -stream handles large files with low memory.
openssl cms -encrypt \
  -binary -stream \
  -aes-256-gcm \
  -in  "${IN}" \
  -out "${tmp}" \
  -outform DER \
  "${RECIP}"

# Atomic move
mv -f -- "${tmp}" "${OUT}"
echo "[encrypt] ✅ Wrote CMS envelope: ${OUT}"
