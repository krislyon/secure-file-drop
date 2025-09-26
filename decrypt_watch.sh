#!/usr/bin/env bash
set -euo pipefail

# === Config (can be overridden by env or .env) ===
WATCH_DIR="${WATCH_DIR:-/secure/inbox}"         # where .cms files arrive
OUT_DIR="${OUT_DIR:-/secure/outbox}"            # where decrypted files go
PROCESSED_DIR="${PROCESSED_DIR:-/secure/processed}"  # archive original envelopes
ERROR_DIR="${ERROR_DIR:-/secure/error}"         # envelopes that failed to decrypt
PRIVKEY_JSON="${PRIVKEY_JSON:-/secure/keys/private_key_encrypted.json}"  # encrypted private key JSON
PASSIN_OPT="${PASSIN_OPT:-ask}"                 # how to supply pass (ask|env:VAR|pass:****)

# Polling interval (seconds) if inotifywait not available
POLL_SEC="${POLL_SEC:-2}"

log()   { printf "%s %s\n" "$(date -Iseconds)" "$*"; }
warn()  { log "WARN: $*"; }
error() { log "ERR: $*"; }

mkdir -p "$WATCH_DIR" "$OUT_DIR" "$PROCESSED_DIR" "$ERROR_DIR"

ensure_private_dir() {
  local dir="$1" mode="$2" label="$3"

  if [[ -z "$dir" ]]; then
    return
  fi

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
  case "${PASSIN_OPT}" in
    ask)
      if [[ ! -t 0 ]]; then
        error "[pass] PASSIN_OPT=ask but no TTY available to prompt for passphrase."
        error "[pass] Provide PASSIN_OPT (e.g. env:VAR or pass:****) or run interactively."
        exit 1
      fi
      local passphrase
      read -r -s -p "Enter passphrase for private key (${PRIVKEY_JSON}): " passphrase || {
        echo
        error "[pass] Unable to read passphrase from terminal."
        exit 1
      }
      echo
      export SFD_PQ_PRIV_PASSPHRASE="$passphrase"
      trap 'unset -v SFD_PQ_PRIV_PASSPHRASE' EXIT
      if [[ -n "$passphrase" ]]; then
        log "[pass] Cached private key passphrase from terminal."
      else
        log "[pass] Using empty passphrase for private key."
      fi
      ;;
    env:*)
      local var="${PASSIN_OPT#env:}"
      if [[ -z "$var" ]]; then
        error "[pass] PASSIN_OPT env: requires a variable name"
        exit 1
      fi
      local value="${!var-}"
      if [[ -z "${value}" ]]; then
        error "[pass] Environment variable ${var} is not set"
        exit 1
      fi
      export SFD_PQ_PRIV_PASSPHRASE="$value"
      ;;
    pass:*)
      export SFD_PQ_PRIV_PASSPHRASE="${PASSIN_OPT#pass:}"
      ;;
    '')
      unset -v SFD_PQ_PRIV_PASSPHRASE
      ;;
    *)
      error "[pass] Unsupported PASSIN_OPT=${PASSIN_OPT}"
      exit 1
      ;;
  esac
}

validate_private_key() {
  if [[ ! -r "$PRIVKEY_JSON" ]]; then
    error "[pass] Private key ${PRIVKEY_JSON} is missing or unreadable"
    exit 1
  fi
  if ! SFD_PQ_PRIV_PASSPHRASE="${SFD_PQ_PRIV_PASSPHRASE-}" node "$(dirname "$0")/tools/validate_private_key.js" "$PRIVKEY_JSON" >/dev/null 2>&1; then
    error "[pass] Unable to unlock private key with provided passphrase (${PRIVKEY_JSON})."
    exit 1
  fi
}

cache_passphrase
validate_private_key

decrypt_one() {
  local cms="$1"
  local base out tmp
  base="$(basename -- "$cms")"
  if [[ "$base" == *.cms ]]; then
    out="${OUT_DIR}/${base%.cms}"
  else
    out="${OUT_DIR}/${base}.dec"
  fi
  tmp="${out}.part"

  log "[decrypt] ⏳ Decrypting: $base"
  if SFD_PQ_PRIV_PASSPHRASE="${SFD_PQ_PRIV_PASSPHRASE-}" node "$(dirname "$0")/decrypt_file.js" \
      -k "$PRIVKEY_JSON" \
      -i "$cms" \
      -o "$tmp"
    log "[decrypt]  md5sum $(md5sum -- "$out")"
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

if command -v inotifywait >/dev/null 2>&1; then
  log "[watch] Using inotify on ${WATCH_DIR} (create/moved_to)"
  process_existing
  inotifywait -m -e close_write -e moved_to --format '%w%f' "$WATCH_DIR"   | while IFS= read -r path; do
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
