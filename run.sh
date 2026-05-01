#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ -d .venv ]]; then
  source .venv/bin/activate
fi

python3 scripts/external_domain_baseline.py "$@"

echo
echo "Dashboard:"
echo "  open index.html"
echo "  or run: python3 -m http.server 8080"
echo "Reports:"
echo "  domain_reports/latest_summary.json"
