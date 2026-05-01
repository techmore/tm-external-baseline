#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRON_MARKER="# tm-external-baseline"
CRON_LINE="15 6 * * * cd \"$ROOT_DIR\" && \"$ROOT_DIR/run.sh\" >> \"$ROOT_DIR/domain_reports/scheduled.log\" 2>&1 $CRON_MARKER"

usage() {
  echo "Usage: ./scheduled.sh install|remove|show"
}

case "${1:-}" in
  install)
    mkdir -p "$ROOT_DIR/domain_reports"
    existing="$(crontab -l 2>/dev/null | grep -v "$CRON_MARKER" || true)"
    printf "%s\n%s\n" "$existing" "$CRON_LINE" | sed '/^$/d' | crontab -
    echo "Installed daily scan at 6:15 AM local time."
    ;;
  remove)
    crontab -l 2>/dev/null | grep -v "$CRON_MARKER" | crontab - || true
    echo "Removed scheduled scan."
    ;;
  show)
    crontab -l 2>/dev/null | grep "$CRON_MARKER" || echo "No tm-external-baseline cron entry installed."
    ;;
  *)
    usage
    exit 1
    ;;
esac
