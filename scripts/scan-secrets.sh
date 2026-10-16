#!/usr/bin/env bash
# Shared CI/local gate. Findings expose rule names and paths only.
set -euo pipefail

mode="${1:-history}"
case "$mode" in
  history) scan_args=(--log-opts=--all) ;;
  staged) scan_args=(--pre-commit --staged) ;;
  *) printf '%s\n' 'Usage: scan-secrets.sh [history|staged]' >&2; exit 2 ;;
esac

if [[ "$(gitleaks version)" != '8.30.1' ]]; then
  printf '%s\n' 'Install gitleaks 8.30.1 before running this gate.' >&2
  exit 2
fi

scan_temp="$(mktemp -d)"
trap 'rm -rf "$scan_temp"' EXIT
scan_status=0
gitleaks git . "${scan_args[@]}" --config .gitleaks.toml \
  --ignore-gitleaks-allow --redact=100 --no-banner --no-color \
  --report-format json --report-path "$scan_temp/report.json" \
  >"$scan_temp/scan.log" 2>&1 || scan_status=$?

if [[ "$scan_status" -ne 0 ]]; then
  printf '%s\n' 'Secret scan failed. Findings (rule/path only):' >&2
  python3 - "$scan_temp/report.json" <<'PY'
import json
import sys
from pathlib import Path

report = Path(sys.argv[1])
if report.exists():
    for finding in json.loads(report.read_text()):
        print(json.dumps({"rule": finding["RuleID"], "path": finding["File"]}))
else:
    print("Scanner did not produce a report; check installation/configuration.")
PY
  exit "$scan_status"
fi
printf '%s\n' 'Secret scan passed.'
