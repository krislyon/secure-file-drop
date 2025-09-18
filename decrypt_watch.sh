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

log()   { printf '%s %s\n' "$(date -Iseconds)" "$*"; }
warn()  { log "WARN: $*"; }
error() { log "ERR: $*"; }

mkdir -p "$WATCH_DIR" "$OUT_DIR" "$PROCESSED_DIR" "$ERROR_DIR"

PRIVATE_KEY_VALIDATED=0

ensure_private_dir() {
  local dir="$1" mode="$2" label="$3"

  if [[ -z "$dir" ]]; then
    return
  fi

  # Try to enforce restrictive permissions, but don't abort if we are not the
  # owner (e.g. when the directories were provisioned by root via
  # create_layout.sh). Services running as an unprivileged user still need to
  # proceed even if they cannot chmod the directory themselves.
  if chmod "$mode" "$dir" 2>/dev/null; then
    return
  fi

  local owner
  owner=$(stat -c '%U:%G' "$dir" 2>/dev/null || echo 'unknown')
  warn "[perm] Unable to set ${label:-$dir} permissions to ${mode}; current owner ${owner}. Continuing with existing permissions."
}

ensure_private_dir "$OUT_DIR" 700 "outbox"
ensure_private_dir "$PROCESSED_DIR" 700 "processed"
ensure_private_dir "$ERROR_DIR" 700 "error"

cache_passphrase() {
  # Cache the private key passphrase at startup so we don't get prompted for
  # every file processed. If PASSIN_OPT is already set to something other than
  # "ask", respect it.
  if [[ "${PASSIN_OPT}" != "ask" ]]; then
    return
  fi

  if [[ ! -t 0 ]]; then
    error "[pass] PASSIN_OPT=ask but no TTY available to prompt for passphrase."
    error "[pass] Provide PASSIN_OPT (e.g. env:VAR, file:/path) or run interactively."
    exit 1
  fi

  PASSIN_OPT="env:DECRYPT_WATCH_PASSPHRASE"
  trap 'unset -v DECRYPT_WATCH_PASSPHRASE' EXIT

  while true; do
    local passphrase
    read -r -s -p "Enter passphrase for private key (${PRIVKEY_PK8}) (leave blank if none): " passphrase || {
      echo
      error "[pass] Unable to read passphrase from terminal."
      exit 1
    }
    echo

    # Keep the passphrase only in memory (environment). It will be cleared when
    # the watcher exits via the trap set above.
    export DECRYPT_WATCH_PASSPHRASE="$passphrase"

    if validate_private_key; then
      PRIVATE_KEY_VALIDATED=1
      if [[ -n "$passphrase" ]]; then
        log "[pass] Cached private key passphrase from terminal."
      else
        log "[pass] Using empty passphrase for private key."
      fi
      break
    fi

    unset -v DECRYPT_WATCH_PASSPHRASE
    warn "[pass] Invalid passphrase; please try again."
  done
}

validate_private_key() {
  local -a base_args=(-in "$PRIVKEY_PK8" -passin "$PASSIN_OPT" -nocrypt -out /dev/null)

  if openssl pkcs8 "${base_args[@]}" 2>/dev/null; then
    return 0
  fi

  if openssl pkcs8 -inform DER "${base_args[@]}" 2>/dev/null; then
    return 0
  fi

  error "[pass] Unable to unlock private key with provided passphrase (${PRIVKEY_PK8})."
  return 1
}

cache_passphrase
if (( PRIVATE_KEY_VALIDATED == 0 )) && ! validate_private_key; then
  exit 1
fi

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
