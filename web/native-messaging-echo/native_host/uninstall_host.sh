#!/usr/bin/env bash
set -euo pipefail

MANIFEST_PATH="${HOME}/.config/google-chrome/NativeMessagingHosts/com.example.native_echo.json"

if [[ -f "${MANIFEST_PATH}" ]]; then
    rm -f "${MANIFEST_PATH}"
    echo "Removed: ${MANIFEST_PATH}"
else
    echo "Not installed: ${MANIFEST_PATH}"
fi
