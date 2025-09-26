#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $(basename "$0") -r /path/to/recipient_cert.pem -i INPUT -o OUTPUT
Encrypt INPUT into CMS (DER) using AES-256-GCM content encryption and a
post-quantum (KEM) recipient.
Options:
  -r  Recipient certificate (PEM, contains ML-KEM/X.509 public key)
  -i  Input file (to encrypt)
  -o  Output CMS file (e.g., file.cms)
Environment:
  CMS_KEM_ALG           KEM algorithm (default: ML-KEM-768)
  CMS_WRAP_CIPHER       Key wrapping cipher (default: AES-256-KWP)
  CMS_CONTENT_CIPHER    Content cipher flag (default: aes-256-gcm)
  OPENSSL_BIN           openssl executable to invoke (default: openssl)
Notes:
  * Uses: openssl cms -encrypt (KEMRecipientInfo)
  * Does NOT log secrets. Filenames only.
EOF
}

CMS_KEM_ALG="${CMS_KEM_ALG:-ML-KEM-768}"
CMS_WRAP_CIPHER="${CMS_WRAP_CIPHER:-AES-256-KWP}"
CMS_CONTENT_CIPHER_FLAG="${CMS_CONTENT_CIPHER:-aes-256-gcm}"
CMS_CONTENT_CIPHER_FLAG="${CMS_CONTENT_CIPHER_FLAG,,}"

OPENSSL_BIN="${OPENSSL_BIN:-openssl}"

[ -n "${CMS_KEM_ALG}" ] || { echo "ERR: CMS_KEM_ALG must not be empty" >&2; exit 2; }
[ -n "${CMS_WRAP_CIPHER}" ] || { echo "ERR: CMS_WRAP_CIPHER must not be empty" >&2; exit 2; }
[ -n "${CMS_CONTENT_CIPHER_FLAG}" ] || { echo "ERR: CMS_CONTENT_CIPHER must not be empty" >&2; exit 2; }

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
echo "[encrypt] ⏳ Encrypting '${IN}' → '${OUT}' (CMS, ${CMS_CONTENT_CIPHER_FLAG} / ${CMS_KEM_ALG})…"

cleanup_tmp() {
  rm -f -- "${tmp}" 2>/dev/null || true
}

trap cleanup_tmp EXIT

# -binary preserves exact bytes; -stream handles large files with low memory.
if ! "${OPENSSL_BIN}" cms -encrypt \
    -binary -stream \
    "-${CMS_CONTENT_CIPHER_FLAG}" \
    -in  "${IN}" \
    -out "${tmp}" \
    -outform DER \
    -keyopt "kem_cipher:${CMS_KEM_ALG}" \
    -keyopt "wrap_cipher:${CMS_WRAP_CIPHER}" \
    "${RECIP}"; then
  status=$?
  echo "ERR: openssl cms -encrypt failed (ensure ${CMS_KEM_ALG} KEM support is available)." >&2
  exit "$status"
fi

# Atomic move
mv -f -- "${tmp}" "${OUT}"
trap - EXIT
echo "[encrypt] ✅ Wrote CMS envelope: ${OUT}"
