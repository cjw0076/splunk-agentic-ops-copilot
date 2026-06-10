#!/usr/bin/env bash
# Splunk Agentic Ops — Incident Copilot. One-command synthetic demo.
# Stdlib Python only. No network, no secrets, no live Splunk required.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

CASE_DIR="${1:-data/synthetic/incident-01}"
OUT_DIR="${2:-out}"

export PYTHONPATH="$HERE/src${PYTHONPATH:+:$PYTHONPATH}"

python3 -m splunk_copilot --case-dir "$CASE_DIR" --out "$OUT_DIR"

echo
echo "List all 5 synthetic scenarios with:"
echo "  PYTHONPATH=$HERE/src python3 -m splunk_copilot --list"
echo
echo "Benchmark the agent across ALL scenarios with:"
echo "  PYTHONPATH=$HERE/src python3 eval/run_eval.py"
echo
echo "Launch the live web dashboard with:"
echo "  pip install -r webapp/requirements.txt && ./run_dashboard.sh"
echo
echo "Replay the recorded reasoning + SPL trace with:"
echo "  PYTHONPATH=$HERE/src python3 -m splunk_copilot --replay $OUT_DIR/trace.json"
echo
echo "Run an ad-hoc SPL query against the case with, e.g.:"
echo "  PYTHONPATH=$HERE/src python3 -m splunk_copilot --case-dir $CASE_DIR \\"
echo "    --spl 'index=web uri_path=\"/api/login\" status=401 | stats count by clientip'"
