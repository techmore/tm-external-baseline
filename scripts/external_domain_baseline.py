#!/usr/bin/env python3
"""
External Domain Baseline

Runs a conservative public-facing baseline for domains:
- DNS record collection and change detection
- Website status/header/vendor collection
- Domain email enumeration from public pages and common aliases

Output is written to domain_reports/latest_summary.json for the dashboard and
to a timestamped HTML report for archival review.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import socket
import ssl
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
DOMAINS_PATH = ROOT / "domains.txt"
CONFIG_PATH = ROOT / "scripts" / "config" / "domains.json"
REPORTS_DIR = ROOT / "domain_reports"
HISTORY_PATH = REPORTS_DIR / "external_domain_history.json"
SUMMARY_PATH = REPORTS_DIR / "latest_summary.json"

DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CAA")
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "XFO",
    "x-content-type-options": "XCTO",
    "referrer-policy": "Referrer-Policy",
}
SECURITY_HEADER_DETAILS = {
    "HSTS": "Forces browsers to use HTTPS after the first successful visit.",
    "CSP": "Limits where scripts, frames, and other active content may load from.",
    "XFO": "Reduces clickjacking risk by controlling frame embedding.",
    "XCTO": "Prevents MIME sniffing in supported browsers.",
    "Referrer-Policy": "Controls how much referrer data leaves the site.",
}
VENDOR_PATTERNS = {
    "Analytics": ("google-analytics", "googletagmanager", "gtag", "analytics", "segment", "mixpanel"),
    "Advertising": ("doubleclick", "adsystem", "adroll", "adsense"),
    "Social": ("facebook", "twitter", "x.com", "linkedin", "instagram", "tiktok"),
    "CDN": ("cloudflare", "amazonaws", "akamai", "fastly", "jsdelivr", "unpkg", "cloudfront"),
    "Libraries": (".js", ".css"),
}
COMMON_MAILBOXES = ("admin", "contact", "hello", "info", "security", "support", "webmaster")


@dataclass
class FetchResult:
    url: str
    status: int | None
    headers: dict[str, str]
    body: str
    error: str | None = None


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_domains(domains: list[str]) -> list[str]:
    clean_domains = []
    for domain in domains:
        domain = domain.strip()
        if not domain or domain.startswith("#"):
            continue
        parsed = urlparse(domain if "://" in domain else f"https://{domain}")
        hostname = parsed.hostname or domain
        hostname = hostname.strip().lower()
        if hostname and hostname not in clean_domains:
            clean_domains.append(hostname)
    return clean_domains


def load_domains(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"Missing domain config: {path}")
    if path.suffix == ".txt":
        return normalize_domains(path.read_text().splitlines())
    with path.open() as fh:
        data = json.load(fh)
    return normalize_domains(data.get("domains", []))


def run_command(command: list[str], timeout: int = 10) -> tuple[int, str]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return result.returncode, result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def collect_dns(domain: str) -> dict[str, list[str]]:
    records: dict[str, list[str]] = {}
    dig_available = run_command(["which", "dig"], timeout=3)[0] == 0
    for record_type in DNS_TYPES:
        values: list[str] = []
        if dig_available:
            code, output = run_command(["dig", "+short", record_type, domain], timeout=10)
            if code == 0 and output:
                values = sorted({line.strip() for line in output.splitlines() if line.strip()})
        elif record_type in {"A", "AAAA"}:
            try:
                infos = socket.getaddrinfo(domain, None)
                values = sorted({info[4][0] for info in infos})
            except socket.gaierror:
                values = []
        records[record_type] = values
    return records


def collect_ssl(domain: str) -> dict[str, Any]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "version": ssock.version(),
                    "cipher": ssock.cipher()[0] if ssock.cipher() else None,
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                }
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        return {"error": str(exc)}


def fetch_url(url: str, timeout: int = 12) -> FetchResult:
    request = Request(url, headers={"User-Agent": "CyberSecurityPilot ExternalDomainBaseline/1.0"})
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(750_000)
            content_type = response.headers.get("content-type", "")
            charset = "utf-8"
            if "charset=" in content_type:
                charset = content_type.split("charset=", 1)[1].split(";", 1)[0].strip()
            return FetchResult(
                url=response.geturl(),
                status=response.status,
                headers={key.lower(): value for key, value in response.headers.items()},
                body=raw.decode(charset, errors="replace"),
            )
    except HTTPError as exc:
        body = exc.read(200_000).decode("utf-8", errors="replace")
        return FetchResult(url=url, status=exc.code, headers={key.lower(): value for key, value in exc.headers.items()}, body=body, error=str(exc))
    except (URLError, TimeoutError, ssl.SSLError, ValueError) as exc:
        return FetchResult(url=url, status=None, headers={}, body="", error=str(exc))


def fetch_site(domain: str) -> FetchResult:
    https_result = fetch_url(f"https://{domain}")
    if https_result.status is not None:
        return https_result
    return fetch_url(f"http://{domain}")


def extract_urls(body: str, base_url: str) -> list[str]:
    attrs = re.findall(r"""(?:src|href)=["']([^"']+)["']""", body, flags=re.IGNORECASE)
    urls = []
    for value in attrs:
        absolute = urljoin(base_url, value)
        parsed = urlparse(absolute)
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            urls.append(absolute)
    return sorted(set(urls))


def categorize_vendor(url: str) -> str:
    lower = url.lower()
    for category, patterns in VENDOR_PATTERNS.items():
        if any(pattern in lower for pattern in patterns):
            return category
    return "Other"


def collect_vendors(domain: str, urls: list[str]) -> list[dict[str, str]]:
    vendors = []
    for url in urls:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if host == domain or host.endswith(f".{domain}"):
            continue
        vendors.append({"name": host, "type": categorize_vendor(url), "url": url})
    unique = {(vendor["name"], vendor["type"], vendor["url"]): vendor for vendor in vendors}
    return sorted(unique.values(), key=lambda item: (item["type"], item["name"], item["url"]))


def analyze_security_headers(headers: dict[str, str]) -> dict[str, Any]:
    checks = []
    for header, label in SECURITY_HEADERS.items():
        value = headers.get(header)
        checks.append({
            "name": label,
            "header": header,
            "present": value is not None,
            "value": value,
            "description": SECURITY_HEADER_DETAILS[label],
        })

    exposed = []
    for header in ("server", "x-powered-by", "via"):
        if header in headers:
            exposed.append({"header": header, "value": headers[header]})

    return {
        "checks": checks,
        "present": sum(1 for check in checks if check["present"]),
        "missing": [check for check in checks if not check["present"]],
        "exposedHeaders": exposed,
    }


def run_nikto(domain: str, timeout: int = 90) -> dict[str, Any]:
    if run_command(["which", "nikto"], timeout=3)[0] != 0:
        return {"available": False, "status": "not_installed", "findings": [], "raw": ""}

    command = ["nikto", "-h", f"https://{domain}", "-nointeractive", "-ask", "no"]
    code, output = run_command(command, timeout=timeout)
    findings = []
    for line in output.splitlines():
        clean = line.strip()
        if clean.startswith("+"):
            findings.append(clean.lstrip("+ ").strip())

    return {
        "available": True,
        "status": "completed" if code in (0, 1) else "error",
        "exitCode": code,
        "findings": findings[:40],
        "findingCount": len(findings),
        "raw": output[-8000:],
    }


def enumerate_emails(domain: str, body: str, mx_records: list[str]) -> dict[str, Any]:
    email_pattern = re.compile(rf"\b[A-Z0-9._%+-]+@{re.escape(domain)}\b", re.IGNORECASE)
    discovered = sorted({match.lower() for match in email_pattern.findall(body)})
    aliases = [f"{mailbox}@{domain}" for mailbox in COMMON_MAILBOXES]
    return {
        "mxPresent": bool(mx_records),
        "discovered": discovered,
        "commonAliases": aliases,
        "totalPublicEmails": len(discovered),
    }


def build_report_sections(domain: str, data: dict[str, Any]) -> list[dict[str, Any]]:
    website = data["website"]
    email = data["email"]
    nikto = website.get("nikto", {})
    return [
        {
            "id": "dns",
            "title": "DNS Records",
            "summary": f"{sum(len(values) for values in data['dns'].values())} records observed",
            "items": [
                {"label": record_type, "value": value}
                for record_type, values in data["dns"].items()
                for value in values
            ],
        },
        {
            "id": "website",
            "title": "Website Status, Headers, Vendors",
            "summary": f"HTTP {website.get('status') or 'n/a'} with {len(website.get('vendors', []))} third-party hosts",
            "items": [
                {"label": "Final URL", "value": website.get("url")},
                {"label": "HTTP status", "value": website.get("status")},
                {"label": "TLS", "value": website.get("ssl", {}).get("version") or website.get("ssl", {}).get("error")},
                *[
                    {"label": check["name"], "value": check["value"] or "Missing"}
                    for check in website.get("securityAnalysis", {}).get("checks", [])
                ],
                *[
                    {"label": vendor["type"], "value": f"{vendor['name']} - {vendor['url']}"}
                    for vendor in website.get("vendors", [])
                ],
            ],
        },
        {
            "id": "nikto",
            "title": "Nikto Exposure Scan",
            "summary": f"{nikto.get('findingCount', 0)} findings" if nikto.get("available") else "Nikto not installed",
            "items": [
                {"label": "Finding", "value": finding}
                for finding in nikto.get("findings", [])
            ] or [{"label": "Status", "value": nikto.get("status", "not_run")}],
        },
        {
            "id": "email",
            "title": "Domain Email Enumeration",
            "summary": f"{email['totalPublicEmails']} public emails; MX {'present' if email['mxPresent'] else 'missing'}",
            "items": [
                *[{"label": "Public email", "value": value} for value in email["discovered"]],
                *[{"label": "Common alias", "value": value} for value in email["commonAliases"]],
            ],
        },
    ]


def diff_records(previous: dict[str, Any], current: dict[str, Any]) -> list[dict[str, Any]]:
    changes = []
    for domain, current_domain in current.items():
        previous_domain = previous.get(domain, {})
        for record_type, values in current_domain.get("dns", {}).items():
            old_values = previous_domain.get("dns", {}).get(record_type, [])
            if values != old_values:
                changes.append({
                    "domain": domain,
                    "category": "DNS",
                    "type": record_type,
                    "old": old_values,
                    "new": values,
                })
        old_status = previous_domain.get("website", {}).get("status")
        new_status = current_domain.get("website", {}).get("status")
        if old_status != new_status:
            changes.append({
                "domain": domain,
                "category": "Website",
                "type": "HTTP status",
                "old": old_status,
                "new": new_status,
            })
    return changes


def load_history() -> dict[str, Any]:
    if HISTORY_PATH.exists():
        with HISTORY_PATH.open() as fh:
            return json.load(fh)
    return {"domains": {}}


def save_history(domains: dict[str, Any]) -> None:
    HISTORY_PATH.write_text(json.dumps({"timestamp": utc_now(), "domains": domains}, indent=2))


def build_summary(domains: dict[str, Any], changes: list[dict[str, Any]], report_name: str) -> dict[str, Any]:
    vendor_counts = {category: 0 for category in ("Analytics", "Advertising", "Social", "CDN", "Libraries", "Other")}
    header_counts = {label: 0 for label in SECURITY_HEADERS.values()}
    vendors_table = {}
    sites = []
    sections = []

    for domain, data in domains.items():
        website = data["website"]
        headers = website.get("headers", {})
        for header, label in SECURITY_HEADERS.items():
            if header in headers:
                header_counts[label] += 1
        for vendor in website.get("vendors", []):
            vendor_counts[vendor["type"]] = vendor_counts.get(vendor["type"], 0) + 1
            key = (vendor["name"], vendor["type"])
            vendors_table.setdefault(key, {"name": vendor["name"], "type": vendor["type"], "sites": set(), "status": "observed"})
            vendors_table[key]["sites"].add(domain)
        sites.append({
            "domain": domain,
            "lastChange": data["timestamp"],
            "dnsChanges": sum(1 for change in changes if change["domain"] == domain and change["category"] == "DNS"),
            "vendorCount": len(website.get("vendors", [])),
            "status": website.get("status"),
            "reportFile": report_name,
        })
        sections.extend(build_report_sections(domain, data))

    total_domains = len(domains)
    possible_headers = total_domains * len(SECURITY_HEADERS)
    security_score = round((sum(header_counts.values()) / possible_headers) * 100) if possible_headers else 0
    recent_changes = [
        {
            "domain": change["domain"],
            "description": f"{change['category']} {change['type']} changed",
            "timestamp": utc_now(),
            "details": change,
        }
        for change in changes[:25]
    ]
    dns_records = []
    for domain, data in domains.items():
        for record_type, values in data["dns"].items():
            for value in values[:10]:
                dns_records.append({"domain": domain, "type": record_type, "value": value, "lastChange": data["timestamp"]})

    return {
        "timestamp": utc_now(),
        "totalDomains": total_domains,
        "averageSecurityScore": security_score,
        "contentChanges": sum(1 for change in changes if change["category"] == "Website"),
        "dnsChanges": sum(1 for change in changes if change["category"] == "DNS"),
        "newVendors": sum(len(data["website"].get("vendors", [])) for data in domains.values()),
        "criticalChanges": [
            f"{change['domain']} {change['type']}" for change in changes
            if change["category"] == "DNS" and change["type"] in {"MX", "NS", "TXT"}
        ],
        "vendorTypes": vendor_counts,
        "securityHeaders": header_counts,
        "recentChanges": recent_changes,
        "dnsRecords": dns_records[:100],
        "vendors": [
            {
                "name": vendor["name"],
                "type": vendor["type"],
                "firstSeen": utc_now(),
                "lastChange": utc_now(),
                "status": vendor["status"],
                "siteCount": len(vendor["sites"]),
            }
            for vendor in vendors_table.values()
        ],
        "sites": sites,
        "sections": sections,
        "domains": domains,
        "recentReports": [{"date": utc_now(), "domains": total_domains, "url": report_name}],
    }


def write_html_report(summary: dict[str, Any], report_path: Path) -> None:
    rows = []
    for site in summary["sites"]:
        domain = site["domain"]
        data = summary["domains"][domain]
        rows.append(
            "<tr>"
            f"<td>{html.escape(domain)}</td>"
            f"<td>{html.escape(str(site.get('status')))}</td>"
            f"<td>{site['dnsChanges']}</td>"
            f"<td>{site['vendorCount']}</td>"
            f"<td>{data['email']['totalPublicEmails']}</td>"
            f"<td>{', '.join(html.escape(v) for v in data['dns'].get('MX', [])[:3])}</td>"
            "</tr>"
        )
    report_path.write_text(f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>External Domain Baseline</title>
  <style>
    body {{ margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #07111f; color: #e8f1ff; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 42px 24px; }}
    h1 {{ font-size: 42px; margin: 0 0 10px; }}
    .lede {{ color: #9fb4cc; margin-bottom: 28px; }}
    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 28px; }}
    .stat, table {{ background: rgba(255,255,255,.06); border: 1px solid rgba(130,170,220,.24); border-radius: 8px; }}
    .stat {{ padding: 18px; }}
    .label {{ color: #8ea5bf; font-size: 12px; text-transform: uppercase; letter-spacing: .12em; }}
    .value {{ font-size: 30px; font-weight: 800; margin-top: 6px; }}
    table {{ width: 100%; border-collapse: collapse; overflow: hidden; }}
    th, td {{ padding: 13px 14px; border-bottom: 1px solid rgba(130,170,220,.18); text-align: left; }}
    th {{ color: #a9bad0; font-size: 12px; text-transform: uppercase; letter-spacing: .08em; background: rgba(255,255,255,.04); }}
  </style>
</head>
<body>
  <main>
    <h1>External Domain Baseline</h1>
    <p class="lede">Generated {html.escape(summary['timestamp'])}. Public-facing DNS, website, vendor, and email exposure baseline.</p>
    <section class="stats">
      <div class="stat"><div class="label">Domains</div><div class="value">{summary['totalDomains']}</div></div>
      <div class="stat"><div class="label">Security Score</div><div class="value">{summary['averageSecurityScore']}%</div></div>
      <div class="stat"><div class="label">DNS Changes</div><div class="value">{summary['dnsChanges']}</div></div>
      <div class="stat"><div class="label">Vendors</div><div class="value">{summary['newVendors']}</div></div>
    </section>
    <table>
      <thead><tr><th>Domain</th><th>Status</th><th>DNS Changes</th><th>Vendors</th><th>Public Emails</th><th>MX Records</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </main>
</body>
</html>
""")


def analyze_domain(domain: str, skip_nikto: bool = False) -> dict[str, Any]:
    dns_records = collect_dns(domain)
    site = fetch_site(domain)
    urls = extract_urls(site.body, site.url)
    vendors = collect_vendors(domain, urls)
    security_analysis = analyze_security_headers(site.headers)
    return {
        "timestamp": utc_now(),
        "dns": dns_records,
        "website": {
            "url": site.url,
            "status": site.status,
            "error": site.error,
            "headers": site.headers,
            "securityHeaders": {label: site.headers.get(header) for header, label in SECURITY_HEADERS.items()},
            "securityAnalysis": security_analysis,
            "ssl": collect_ssl(domain),
            "vendors": vendors,
            "nikto": {"available": False, "status": "skipped", "findings": [], "findingCount": 0} if skip_nikto else run_nikto(domain),
        },
        "email": enumerate_emails(domain, site.body, dns_records.get("MX", [])),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run external domain baseline monitoring")
    parser.add_argument("--config", type=Path, default=DOMAINS_PATH, help="Path to domains.txt or domains.json")
    parser.add_argument("--domain", action="append", help="Domain to scan; can be supplied multiple times")
    parser.add_argument("--skip-nikto", action="store_true", help="Skip Nikto web exposure scan")
    args = parser.parse_args()

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    domains = normalize_domains(args.domain) if args.domain else load_domains(args.config)
    if not domains:
        print("No domains configured.", file=sys.stderr)
        return 1

    history = load_history()
    current = {domain: analyze_domain(domain, skip_nikto=args.skip_nikto) for domain in domains}
    changes = diff_records(history.get("domains", {}), current)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_name = f"external_domain_baseline_{timestamp}.html"
    summary = build_summary(current, changes, report_name)

    SUMMARY_PATH.write_text(json.dumps(summary, indent=2))
    write_html_report(summary, REPORTS_DIR / report_name)
    save_history(current)
    print(f"Wrote {SUMMARY_PATH}")
    print(f"Wrote {REPORTS_DIR / report_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
