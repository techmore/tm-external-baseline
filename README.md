# TM External Baseline

Monitor the public-facing assets that attackers, vendors, insurers, and customers see first.

The tool runs locally, stores history locally, and produces a lightweight website/report you can publish with GitHub Pages or serve from any static host.

## What It Checks

- DNS records: `A`, `AAAA`, `MX`, `NS`, `TXT`, `CAA`
- Website status, redirects, TLS, headers, and third-party vendors
- Nikto web exposure findings when `nikto` is installed
- Domain email exposure from public pages plus common mailbox aliases
- Change history between scans

## Quick Start

```bash
git clone https://github.com/techmore/tm-external-baseline.git
cd tm-external-baseline
./install.sh
./run.sh
```

Then open `index.html`, or serve it locally:

```bash
python3 -m http.server 8080
```

Open `http://localhost:8080`.

## Domains

Edit `domains.txt` and put one domain per line:

```text
example.com
school.edu
nonprofit.org
```

Run one-off domains without editing the file:

```bash
./run.sh --domain example.com --domain example.org
```

Skip Nikto for faster scans:

```bash
./run.sh --skip-nikto
```

## Daily Monitoring

Install a daily local cron job:

```bash
./scheduled.sh install
```

Show or remove it:

```bash
./scheduled.sh show
./scheduled.sh remove
```

The scheduled job runs `./run.sh` and appends logs to `domain_reports/scheduled.log`.

## Outputs

- `domain_reports/latest_summary.json`
- `domain_reports/external_domain_baseline_*.html`
- `domain_reports/external_domain_history.json`
- `index.html` and `dashboard/index.html`

The first scan establishes a baseline. Later scans highlight changes.

## Optional System Tools

The scanner works with Python alone, but fuller reports use:

- `dig` for DNS records
- `nikto` for web exposure checks
- `nmap` for future scan integrations

On macOS:

```bash
brew install bind nikto nmap
```

On Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y dnsutils nikto nmap
```

## GitHub Pages

This repository includes a root `index.html`, so GitHub Pages can serve the dashboard directly. Commit `domain_reports/latest_summary.json` when you want the hosted page to show the latest public demo data.
