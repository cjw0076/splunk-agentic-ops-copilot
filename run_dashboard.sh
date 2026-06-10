#!/usr/bin/env bash
# Splunk Incident Copilot — web dashboard. Synthetic data, zero credentials.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
export PYTHONPATH="$HERE/src${PYTHONPATH:+:$PYTHONPATH}"
PORT="${1:-8000}"
echo "Dashboard on http://127.0.0.1:${PORT}  (synthetic, offline, no secrets)"
exec python3 -m uvicorn webapp.server:app --host 127.0.0.1 --port "$PORT"
