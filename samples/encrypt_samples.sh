#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLES_DIR="${SCRIPT_DIR}"
ENCRYPT_SCRIPT="${SCRIPT_DIR}/../encrypt_file.sh"
DEFAULT_OUTPUT_DIR="/secure/inbox"

usage() {
  cat <<EOF
Usage: $(basename "${BASH_SOURCE[0]}") [-o OUTPUT_DIR]

Encrypt all non-CMS sample files using encrypt_file.sh and write them to
the specified OUTPUT_DIR (defaults to ${DEFAULT_OUTPUT_DIR}).
EOF
}

OUTPUT_DIR="${DEFAULT_OUTPUT_DIR}"

while getopts ":o:h" opt; do
  case "${opt}" in
    o) OUTPUT_DIR="${OPTARG}" ;;
    h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
done
shift $(( OPTIND - 1 ))

if [[ ! -x "${ENCRYPT_SCRIPT}" ]]; then
  echo "ERR: Unable to find executable encrypt_file.sh at ${ENCRYPT_SCRIPT}" >&2
  exit 1
fi

printf 'Sample directory: %s\n' "${SAMPLES_DIR}"
printf 'Encrypt helper: %s\n' "${ENCRYPT_SCRIPT}"
printf 'Output directory: %s\n' "${OUTPUT_DIR}"

if [[ ! -d "${OUTPUT_DIR}" ]]; then
  echo "Creating output directory: ${OUTPUT_DIR}"
  mkdir -p -- "${OUTPUT_DIR}"
fi

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
  output_path="${OUTPUT_DIR}/${name}.cms"
  printf 'Encrypting %s -> %s\n' "${name}" "${output_path}"
  "${ENCRYPT_SCRIPT}" -r "${RECIP_CERT}" -i "${input_path}" -o "${output_path}"
done

echo "All sample files encrypted."
