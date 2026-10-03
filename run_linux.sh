#!/usr/bin/env bash
# Start AYYSCANNER (Linux / macOS). Extra arguments are passed through.
cd "$(dirname "$0")" || exit 1
PY=python3
command -v python3 >/dev/null 2>&1 || PY=python
exec "$PY" run.py "$@"
