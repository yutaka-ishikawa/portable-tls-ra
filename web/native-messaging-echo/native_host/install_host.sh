#!/usr/bin/env bash
set -euo pipefail

HOST_NAME="com.example.native_echo"

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <CHROME_EXTENSION_ID>" >&2
    echo "Example: $0 abcdefghijklmnopqrstuvwxyzabcdef" >&2
    exit 1
fi

EXTENSION_ID="$1"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HOST_BIN="${SCRIPT_DIR}/echo_host"

if [[ ! -x "${HOST_BIN}" ]]; then
    echo "Error: ${HOST_BIN} does not exist or is not executable." >&2
    echo "Run: make" >&2
    exit 1
fi

case "${EXTENSION_ID}" in
    *[!a-p]*|"")
        echo "Warning: '${EXTENSION_ID}' does not look like a normal Chrome extension ID." >&2
        ;;
esac

INSTALL_DIR="${HOME}/.config/google-chrome/NativeMessagingHosts"
MANIFEST_PATH="${INSTALL_DIR}/${HOST_NAME}.json"

mkdir -p "${INSTALL_DIR}"

python3 - "${SCRIPT_DIR}/com.example.native_echo.json.template" \
          "${MANIFEST_PATH}" \
          "${HOST_BIN}" \
          "${EXTENSION_ID}" <<'PY'
import json
import pathlib
import sys

template_path = pathlib.Path(sys.argv[1])
output_path = pathlib.Path(sys.argv[2])
host_path = str(pathlib.Path(sys.argv[3]).resolve())
extension_id = sys.argv[4]

data = json.loads(template_path.read_text())
data["path"] = host_path
data["allowed_origins"] = [f"chrome-extension://{extension_id}/"]
output_path.write_text(json.dumps(data, indent=2) + "\n")
PY

echo "Installed Native Messaging manifest:"
echo "  ${MANIFEST_PATH}"
echo
echo "Host binary:"
echo "  ${HOST_BIN}"
echo
echo "Allowed extension:"
echo "  chrome-extension://${EXTENSION_ID}/"
