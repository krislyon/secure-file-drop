#!/usr/bin/env bash
set -euo pipefail

# === Config (can be overridden by env or .env) ===
WATCH_DIR="${WATCH_DIR:-/secure/inbox}"         # where .cms files arrive
OUT_DIR="${OUT_DIR:-/secure/outbox}"            # where decrypted files go
PROCESSED_DIR="${PROCESSED_DIR:-/secure/processed}"  # archive original envelopes
ERROR_DIR="${ERROR_DIR:-/secure/error}"         # envelopes that failed to decrypt
CERT_PEM="${CERT_PEM:-/secure/keys/cert.pem}"   # recipient cert (PEM)
PRIVKEY_PK8="${PRIVKEY_PK8:-/secure/keys/privkey_encrypted.pk8}"  # encrypted PKCS#8
PASSIN_OPT="${PASSIN_OPT:-ask}"                 # how to supply pass (ask|fd:3|pass:****)

# Polling interval (seconds) if inotifywait not available
POLL_SEC="${POLL_SEC:-2}"

mkdir -p "$WATCH_DIR" "$OUT_DIR" "$PROCESSED_DIR" "$ERROR_DIR"
chmod 700 "$OUT_DIR" "$PROCESSED_DIR" "$ERROR_DIR"

log()   { printf '%s %s\n' "$(date -Iseconds)" "$*"; }
warn()  { log "WARN: $*"; }
error() { log "ERR: $*"; }

decrypt_one() {
  local cms="$1"
  local base out tmp
  base="$(basename -- "$cms")"
  # Drop final .cms; if absent, just append .dec
  if [[ "$base" == *.cms ]]; then
    out="${OUT_DIR}/${base%.cms}"
  else
    out="${OUT_DIR}/${base}.dec"
  fi
  tmp="${out}.part"

  log "[decrypt] ⏳ Decrypting: $base"
  if openssl cms -decrypt -binary -inform DER \
      -in "$cms" \
      -out "$tmp" \
      -recip "$CERT_PEM" \
      -inkey "$PRIVKEY_PK8" -passin "$PASSIN_OPT"
  then
    mv -f -- "$tmp" "$out"
    log "[decrypt] ✅ OK → ${out}"
    mv -f -- "$cms" "${PROCESSED_DIR}/${base}"
  else
    rm -f -- "$tmp" || true
    error "[decrypt] ❌ Failed: ${base} (moved to ${ERROR_DIR})"
    mv -f -- "$cms" "${ERROR_DIR}/${base}"
  fi
}

process_existing() {
  shopt -s nullglob
  for f in "$WATCH_DIR"/*.cms; do
    decrypt_one "$f"
  done
}

# Try inotify if available; else poll
if command -v inotifywait >/dev/null 2>&1; then
  log "[watch] Using inotify on ${WATCH_DIR} (create/moved_to)"
  process_existing
  inotifywait -m -e close_write -e moved_to --format '%w%f' "$WATCH_DIR" \
  | while IFS= read -r path; do
      [[ "$path" == *.cms ]] || continue
      decrypt_one "$path"
    done
else
  warn "[watch] inotifywait not found; falling back to ${POLL_SEC}s polling."
  while true; do
    process_existing
    sleep "$POLL_SEC"
  done
fi
