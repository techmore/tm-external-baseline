#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "External Domain Baseline installer"
echo "Repository: $ROOT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required. Install Python 3.10+ and rerun this script." >&2
  exit 1
fi

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi

source .venv/bin/activate
python -m pip install --upgrade pip >/dev/null
if [[ -s requirements.txt ]]; then
  python -m pip install -r requirements.txt
fi

missing_tools=()
for tool in dig nikto nmap; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing_tools+=("$tool")
  fi
done

if (( ${#missing_tools[@]} > 0 )); then
  echo "Optional system tools missing: ${missing_tools[*]}"
  if command -v brew >/dev/null 2>&1; then
    echo "On macOS, install them with: brew install bind nikto nmap"
  elif command -v apt-get >/dev/null 2>&1; then
    echo "On Debian/Ubuntu, install them with: sudo apt-get update && sudo apt-get install -y dnsutils nikto nmap"
  else
    echo "Install dig, nikto, and nmap with your OS package manager for full reports."
  fi
else
  echo "Found dig, nikto, and nmap."
fi

if [[ ! -f domains.txt ]]; then
  touch domains.txt
fi

if [[ -t 0 ]]; then
  echo
  read -r -p "Enter domains to monitor daily, separated by spaces (leave blank to keep domains.txt): " domains
  if [[ -n "${domains// }" ]]; then
    {
      echo "# One domain per line. Schemes and paths are optional."
      for domain in $domains; do
        echo "$domain"
      done
    } > domains.txt
    echo "Updated domains.txt"
  fi
fi

mkdir -p domain_reports
echo "Install complete."
echo "Run a scan with: ./run.sh"
echo "Install a daily cron scan with: ./scheduled.sh install"
