#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRON_MARKER="# tm-external-baseline"
CRON_LINE="15 6 * * * cd \"$ROOT_DIR\" && \"$ROOT_DIR/run.sh\" >> \"$ROOT_DIR/domain_reports/scheduled.log\" 2>&1 $CRON_MARKER"
WEEKLY_CRON_MARKER="# tm-external-baseline-weekly"
WEEKLY_CRON_LINE="30 7 * * 1 cd \"$ROOT_DIR\" && \"$ROOT_DIR/scheduled.sh\" weekly-summary >> \"$ROOT_DIR/domain_reports/scheduled.log\" 2>&1 $WEEKLY_CRON_MARKER"

usage() {
  echo "Usage: ./scheduled.sh install|install-weekly|remove|show|weekly-summary"
}

case "${1:-}" in
  install)
    mkdir -p "$ROOT_DIR/domain_reports"
    existing="$(crontab -l 2>/dev/null | grep -v "$CRON_MARKER" || true)"
    printf "%s\n%s\n" "$existing" "$CRON_LINE" | sed '/^$/d' | crontab -
    echo "Installed daily scan at 6:15 AM local time."
    ;;
  install-weekly)
    mkdir -p "$ROOT_DIR/domain_reports"
    existing="$(crontab -l 2>/dev/null | grep -v "$WEEKLY_CRON_MARKER" || true)"
    printf "%s\n%s\n" "$existing" "$WEEKLY_CRON_LINE" | sed '/^$/d' | crontab -
    echo "Installed weekly summary at 7:30 AM local time on Mondays."
    ;;
  remove)
    crontab -l 2>/dev/null | grep -v "$CRON_MARKER" | grep -v "$WEEKLY_CRON_MARKER" | crontab - || true
    echo "Removed scheduled scans and weekly summaries."
    ;;
  show)
    crontab -l 2>/dev/null | grep "tm-external-baseline" || echo "No tm-external-baseline cron entry installed."
    ;;
  weekly-summary)
    mkdir -p "$ROOT_DIR/domain_reports"
    python3 - "$ROOT_DIR" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
summary_path = root / "domain_reports" / "latest_summary.json"
if not summary_path.exists():
    raise SystemExit("No latest_summary.json found. Run ./run.sh first.")
data = json.loads(summary_path.read_text())
lines = [
    "# External Domain Baseline Weekly Summary",
    "",
    f"Generated: {datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')}",
    f"Latest scan: {data.get('timestamp')}",
    f"Domains monitored: {data.get('totalDomains', 0)}",
    "",
    "## Scorecard",
]
for item in data.get("scorecard", []):
    lines.append(f"- {item.get('area')}: {item.get('status')} - {item.get('summary')}")
lines.extend(["", "## Top Findings"])
for finding in data.get("findings", [])[:10]:
    lines.append(f"- [{finding.get('severity')}] {finding.get('title')} ({finding.get('domain')})")
lines.extend(["", "## Remediation"])
for task in data.get("remediation", [])[:10]:
    lines.append(f"- [{task.get('severity')}] {task.get('task')}")
output = root / "domain_reports" / f"weekly_summary_{datetime.now(timezone.utc).strftime('%Y%m%d')}.md"
output.write_text("\n".join(lines) + "\n")
print(f"Wrote {output}")
PY
    ;;
  *)
    usage
    exit 1
    ;;
esac
