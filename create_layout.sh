#!/usr/bin/env bash
set -euo pipefail

# Defaults (change if you like)
SECURE_ROOT="${SECURE_ROOT:-/secure}"
USER_NAME="${USER_NAME:-decryptd}"
GROUP_NAME="${GROUP_NAME:-decryptd}"

MAKE_USER=0
MAKE_TMPFILES=0

usage() {
  cat <<EOF
Usage: sudo $(basename "$0") [options]

Creates the recommended directory layout:

  \$SECURE_ROOT/
    inbox/ outbox/ processed/ error/ keys/

Sets ownership to root:\$GROUP_NAME and permissions 0750 on dirs,
and 0640 on any existing files inside keys/ (if present).

Options:
  --root /path        Base directory (default: ${SECURE_ROOT})
  --user NAME         Service user/group name (default: ${USER_NAME})
  --make-user         Create a system user/group if missing
  --tmpfiles          Install /etc/tmpfiles.d/decrypt-watch.conf
  -h, --help          Show this help

Env overrides:
  SECURE_ROOT=/secure_alt  USER_NAME=decryptd  GROUP_NAME=decryptd
Examples:
  sudo ./create_layout.sh --make-user --tmpfiles
  sudo SECURE_ROOT=/data/secure ./create_layout.sh
EOF
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)       SECURE_ROOT="$2"; shift 2 ;;
    --user)       USER_NAME="$2"; GROUP_NAME="$2"; shift 2 ;;
    --make-user)  MAKE_USER=1; shift ;;
    --tmpfiles)   MAKE_TMPFILES=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

# Must be root
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "ERR: please run as root (or with sudo)"; exit 1
fi

log() { printf '%s %s\n' "$(date -Iseconds)" "$*"; }

# Create service account if requested
if [[ $MAKE_USER -eq 1 ]]; then
  if ! id -u "$USER_NAME" >/dev/null 2>&1; then
    log "[acct] Creating system user/group: ${USER_NAME}"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
  else
    log "[acct] User exists: ${USER_NAME}"
  fi
fi

# Ensure group exists (some distros separate group creation)
if ! getent group "$GROUP_NAME" >/dev/null 2>&1; then
  log "[acct] Creating group: ${GROUP_NAME}"
  groupadd --system "$GROUP_NAME"
fi

# Create directories
umask 027  # default new files: 0640, dirs: 0750
for d in "" inbox outbox processed error keys; do
  dir="${SECURE_ROOT%/}/${d:+$d/}"
  dir="${dir%/}"  # strip trailing /
  mkdir -p "$dir"
  chmod 0750 "$dir"
  chown root:"$GROUP_NAME" "$dir"
  log "[fs] Ensured: $dir (0750 root:${GROUP_NAME})"
done

# Tighten key files if they already exist (no secrets printed)
KEYS_DIR="${SECURE_ROOT%/}/keys"
if compgen -G "${KEYS_DIR}/*" >/dev/null 2>&1; then
  while IFS= read -r -d '' f; do
    # regular files only
    if [[ -f "$f" ]]; then
      chmod 0640 "$f" || true
      chown root:"$GROUP_NAME" "$f" || true
      log "[fs] Key file perms set: $f → 0640 root:${GROUP_NAME}"
    fi
  done < <(find "$KEYS_DIR" -maxdepth 1 -type f -print0)
fi

# Optional tmpfiles rule
if [[ $MAKE_TMPFILES -eq 1 ]]; then
  RULE="/etc/tmpfiles.d/decrypt-watch.conf"
  cat > "$RULE" <<EOF
d ${SECURE_ROOT}               0750 root ${GROUP_NAME} -
d ${SECURE_ROOT}/inbox         0750 root ${GROUP_NAME} -
d ${SECURE_ROOT}/outbox        0750 root ${GROUP_NAME} -
d ${SECURE_ROOT}/processed     0750 root ${GROUP_NAME} -
d ${SECURE_ROOT}/error         0750 root ${GROUP_NAME} -
d ${SECURE_ROOT}/keys          0750 root ${GROUP_NAME} -
EOF
  chmod 0644 "$RULE"
  log "[tmpfiles] Installed: $RULE"
  if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create "$RULE"
    log "[tmpfiles] Applied tmpfiles rule"
  else
    log "[tmpfiles] systemd-tmpfiles not found; rule will apply at boot"
  fi
fi

log "[done] Layout ready under ${SECURE_ROOT}"
