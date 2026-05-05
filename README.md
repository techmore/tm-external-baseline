# TM External Baseline

Monitor the public-facing assets that attackers, vendors, insurers, and customers see first.

The tool runs locally, stores history locally, and produces a lightweight website/report you can publish with GitHub Pages or serve from any static host.

## What It Checks

- DNS records: `A`, `AAAA`, `MX`, `NS`, `TXT`, `CAA`
- Website status, redirects, TLS, headers, and third-party vendors
- Nikto web exposure findings when `nikto` is installed
- Domain email exposure from public pages plus common mailbox aliases
- SPF, DKIM selector discovery, DMARC policy strength, MX provider, and spoofing risk
- Change history between scans
- Plain-English findings with impact, recommendation, confidence, owner, severity, and effort
- Customer scorecards using `Pass`, `Watch`, and `Action Needed`
- Remediation checklist tasks

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

## Customer Output

Each scan generates:

- Customer scorecard
- Plain-English findings
- Before/after change timeline
- Email authentication health for SPF, DKIM, and DMARC
- Vendor risk labels
- Remediation checklist
- HTML report suitable for browser print-to-PDF

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

Optional alert environment variables:

```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export SMTP_HOST="smtp.example.com"
export SMTP_PORT="587"
export SMTP_USERNAME="user"
export SMTP_PASSWORD="password"
export SMTP_FROM="baseline@example.com"
export SMTP_TO="security@example.com"
```

Alerts are sent only when high-priority findings or changes are present.

## Outputs

- `domain_reports/latest_summary.json`
- `domain_reports/public_summary.json`
- `domain_reports/external_domain_baseline_*.html`
- `domain_reports/external_domain_history.json`
- `index.html` and `dashboard/index.html`

The first scan establishes a baseline. Later scans highlight changes.

`latest_summary.json` and timestamped HTML reports contain raw technical evidence. Use `public_summary.json` for safer publishing when you do not want to expose DNS evidence, discovered public emails, Nikto output, or raw headers.

## Optional System Tools

The scanner installs `dnspython` for DNS lookups. If `dig` is available, it will use `dig`; otherwise it falls back to Python DNS resolution. Fuller reports can also use:

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

This repository includes a root `index.html`, so GitHub Pages can serve the dashboard directly.

Do not publish customer `latest_summary.json` or timestamped HTML reports unless the customer explicitly wants that evidence public. Those files can contain raw DNS data, public email discoveries, vendors, headers, and Nikto output. Prefer publishing `domain_reports/public_summary.json` or a purpose-built demo dataset.
