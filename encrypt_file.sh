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

log()   { printf '%s %s\n' "$(date -Iseconds)" "$*"; }
warn()  { log "WARN: $*"; }
error() { log "ERR: $*"; }

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

[ -n "${RECIP}" ] && [ -f "${RECIP}" ] || { error "[encrypt] recipient cert missing"; exit 2; }
[ -n "${IN}" ] && [ -f "${IN}" ] || { error "[encrypt] input file missing"; exit 2; }
[ -n "${OUT}" ] || { error "[encrypt] output path missing"; exit 2; }

tmp="${OUT}.part"

supports_gcm() {
  local cipher_list tmpfile

  # OpenSSL 3.x exposes algorithm availability via `list -cipher-algorithms`.
  if cipher_list=$(openssl list -cipher-algorithms 2>/dev/null); then
    if grep -qi 'aes-256-gcm' <<<"${cipher_list}"; then
      return 0
    fi
  fi

  # OpenSSL 1.1.1 exposes cipher names via `list -cipher-commands`.
  if cipher_list=$(openssl list -cipher-commands 2>/dev/null); then
    if grep -qi 'aes-256-gcm' <<<"${cipher_list}"; then
      return 0
    fi
  fi

  # As a final fallback, attempt a tiny CMS envelope to confirm support.
  tmpfile=$(mktemp) || return 1
  if openssl cms -encrypt \
    -binary -stream \
    -aes-256-gcm \
    -in /dev/null \
    -out "${tmpfile}" \
    -outform DER \
    -recip "${RECIP}" >/dev/null 2>&1; then
    rm -f -- "${tmpfile}"
    return 0
  fi

  rm -f -- "${tmpfile}"
  return 1
}

CMS_CIPHER=(-aes-256-gcm)
CIPHER_LABEL="AES-256-GCM"
if ! supports_gcm; then
  warn "[encrypt] ⚠️ OpenSSL lacks AES-256-GCM support; falling back to AES-256-CBC."
  CMS_CIPHER=(-aes256)
  CIPHER_LABEL="AES-256-CBC"
  warn "[encrypt] ℹ️ Resulting envelope will not provide built-in authentication."
fi

log "[encrypt] ⏳ Encrypting '${IN}' → '${OUT}' (CMS, ${CIPHER_LABEL})…"
log "[encrypt] 🔐 md5sum $(md5sum -- "${IN}")"

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
log "[encrypt] ✅ Wrote CMS envelope: ${OUT}"
