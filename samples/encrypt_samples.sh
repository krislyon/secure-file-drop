#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLES_DIR="${SCRIPT_DIR}"
ENCRYPT_SCRIPT="${SCRIPT_DIR}/../encrypt_file.sh"

if [[ ! -x "${ENCRYPT_SCRIPT}" ]]; then
  echo "ERR: Unable to find executable encrypt_file.sh at ${ENCRYPT_SCRIPT}" >&2
  exit 1
fi

printf 'Sample directory: %s\n' "${SAMPLES_DIR}"
printf 'Encrypt helper: %s\n' "${ENCRYPT_SCRIPT}"

shopt -s nullglob
files=()
for path in "${SAMPLES_DIR}"/*; do
  [[ -f "${path}" ]] || continue
  base_name="$(basename "${path}")"
  [[ "${base_name}" == "$(basename "${BASH_SOURCE[0]}")" ]] && continue
  [[ "${base_name}" == *.cms ]] && continue
  files+=("${base_name}")
done
shopt -u nullglob

if (( ${#files[@]} == 0 )); then
  echo "No sample files to encrypt in ${SAMPLES_DIR}." >&2
  exit 0
fi

echo "Files to encrypt:"
for name in "${files[@]}"; do
  printf '  - %s\n' "${name}"
done

read -rp "Enter path to recipient certificate: " RECIP_CERT
if [[ ! -f "${RECIP_CERT}" ]]; then
  echo "ERR: Certificate file not found: ${RECIP_CERT}" >&2
  exit 2
fi

for name in "${files[@]}"; do
  input_path="${SAMPLES_DIR}/${name}"
  output_path="${input_path}.cms"
  printf 'Encrypting %s -> %s\n' "${name}" "$(basename "${output_path}")"
  "${ENCRYPT_SCRIPT}" -r "${RECIP_CERT}" -i "${input_path}" -o "${output_path}"
done

echo "All sample files encrypted."
