#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $(basename "$0") -r /path/to/recipient_pub.json -i INPUT -o OUTPUT
Encrypt INPUT into an SFD PQC envelope using AES-256-GCM and an LWE-based KEM.
Options:
  -r  Recipient public key (JSON)
  -i  Input file (to encrypt)
  -o  Output envelope file (e.g., file.cms)
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

[ -n "${RECIP}" ] && [ -f "${RECIP}" ] || { echo "ERR: recipient key missing"; exit 2; }
[ -n "${IN}" ] && [ -f "${IN}" ] || { echo "ERR: input file missing"; exit 2; }
[ -n "${OUT}" ] || { echo "ERR: output path missing"; exit 2; }

node "$(dirname "$0")/encrypt_file.js" -r "$RECIP" -i "$IN" -o "$OUT"
