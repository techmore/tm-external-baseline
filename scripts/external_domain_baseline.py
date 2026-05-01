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
import hashlib
import html
import json
import os
import re
import smtplib
import socket
import ssl
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
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
    "Fonts": ("fonts.googleapis.com", "fonts.gstatic.com", "typekit", "fontawesome"),
    "Payment": ("stripe", "paypal", "squareup", "checkout", "authorize.net", "braintree"),
    "Marketing": ("hubspot", "mailchimp", "constantcontact", "marketo", "pardot", "intercom"),
    "CDN": ("cloudflare", "amazonaws", "akamai", "fastly", "jsdelivr", "unpkg", "cloudfront"),
    "Libraries": (".js", ".css"),
}
COMMON_MAILBOXES = ("admin", "contact", "hello", "info", "security", "support", "webmaster")
COMMON_DKIM_SELECTORS = ("google", "selector1", "selector2", "default", "k1", "mail", "s1", "s2")
SEVERITY_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}


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


def resolve_txt(name: str) -> list[str]:
    code, output = run_command(["dig", "+short", "TXT", name], timeout=10)
    if code != 0 or not output:
        return []
    return sorted({line.strip().replace('" "', "") for line in output.splitlines() if line.strip()})


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
    return "Unknown"


def collect_vendors(domain: str, urls: list[str]) -> list[dict[str, str]]:
    vendors = []
    for url in urls:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if host == domain or host.endswith(f".{domain}"):
            continue
        category = categorize_vendor(url)
        vendors.append({
            "name": host,
            "type": category,
            "category": category,
            "riskLabel": "Watch" if category == "Unknown" else "Observed",
            "reason": f"Matched {category.lower()} pattern" if category != "Unknown" else "No known category pattern matched",
            "url": url,
        })
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
    spf_records = [value for value in resolve_txt(domain) if "v=spf1" in value.lower()]
    dmarc_records = [value for value in resolve_txt(f"_dmarc.{domain}") if "v=dmarc1" in value.lower()]
    dkim_records = []
    for selector in COMMON_DKIM_SELECTORS:
        records = resolve_txt(f"{selector}._domainkey.{domain}")
        if records:
            dkim_records.append({"selector": selector, "records": records})
    mx_provider = identify_mx_provider(mx_records)
    dmarc_policy = "missing"
    if dmarc_records:
        match = re.search(r"\bp=(none|quarantine|reject)\b", " ".join(dmarc_records), re.IGNORECASE)
        dmarc_policy = match.group(1).lower() if match else "present"
    spoofing_risk = "Low"
    if not spf_records and not dmarc_records:
        spoofing_risk = "High"
    elif not dmarc_records or dmarc_policy == "none":
        spoofing_risk = "Medium"
    spf_status = "Pass" if spf_records else "Action Needed"
    dmarc_status = "Pass" if dmarc_policy in {"quarantine", "reject"} else ("Watch" if dmarc_policy == "none" else "Action Needed")
    dkim_status = "Pass" if dkim_records else "Watch"
    overall_status = "Action Needed" if "Action Needed" in {spf_status, dmarc_status} else ("Watch" if "Watch" in {spf_status, dmarc_status, dkim_status} else "Pass")
    return {
        "mxPresent": bool(mx_records),
        "mxRecords": mx_records,
        "mxProvider": mx_provider,
        "spf": {"present": bool(spf_records), "records": spf_records, "valid": bool(spf_records)},
        "dmarc": {"present": bool(dmarc_records), "records": dmarc_records, "policy": dmarc_policy},
        "dkim": {"selectorsChecked": list(COMMON_DKIM_SELECTORS), "records": dkim_records, "present": bool(dkim_records)},
        "health": {
            "overall": overall_status,
            "spf": {
                "status": spf_status,
                "label": "SPF",
                "summary": "SPF record found" if spf_records else "SPF record missing",
                "whyItMatters": "SPF tells receiving mail servers which systems may send mail for this domain.",
            },
            "dkim": {
                "status": dkim_status,
                "label": "DKIM",
                "summary": f"{len(dkim_records)} selector(s) discovered" if dkim_records else "No common DKIM selectors discovered",
                "whyItMatters": "DKIM cryptographically signs outbound mail so receivers can verify message authenticity.",
            },
            "dmarc": {
                "status": dmarc_status,
                "label": "DMARC",
                "summary": f"DMARC policy: {dmarc_policy}" if dmarc_records else "DMARC record missing",
                "whyItMatters": "DMARC tells receivers what to do when SPF or DKIM authentication fails.",
            },
        },
        "spoofingRisk": spoofing_risk,
        "discovered": discovered,
        "commonAliases": aliases,
        "totalPublicEmails": len(discovered),
    }


def identify_mx_provider(mx_records: list[str]) -> str:
    joined = " ".join(mx_records).lower()
    providers = {
        "Google Workspace": ("google.com", "googlemail.com", "smtp.google.com"),
        "Microsoft 365": ("protection.outlook.com", "outlook.com"),
        "Proofpoint": ("pphosted.com",),
        "Mimecast": ("mimecast.com",),
        "Fastmail": ("messagingengine.com",),
        "Zoho": ("zoho.com",),
        "Hover": ("hover.com",),
    }
    for provider, patterns in providers.items():
        if any(pattern in joined for pattern in patterns):
            return provider
    return "Unknown" if mx_records else "No MX"


def stable_id(*parts: Any) -> str:
    text = "|".join(str(part) for part in parts)
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:12]


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
                    {"label": vendor["category"], "value": f"{vendor['name']} - {vendor['url']}"}
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
            "title": "Email Authentication Health",
            "summary": f"{email['health']['overall']}: SPF {email['health']['spf']['status']}, DKIM {email['health']['dkim']['status']}, DMARC {email['health']['dmarc']['status']}",
            "items": [
                {"label": "MX provider", "value": email["mxProvider"]},
                {"label": "SPF", "value": email["health"]["spf"]["summary"]},
                {"label": "DKIM", "value": email["health"]["dkim"]["summary"]},
                {"label": "DMARC", "value": email["health"]["dmarc"]["summary"]},
                {"label": "Spoofing risk", "value": email["spoofingRisk"]},
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
            added = sorted(set(values) - set(old_values))
            removed = sorted(set(old_values) - set(values))
            if added or removed:
                changes.append({
                    "id": stable_id(domain, "dns", record_type, json.dumps(added), json.dumps(removed)),
                    "domain": domain,
                    "category": "DNS",
                    "type": record_type,
                    "changeType": "dns_record_changed",
                    "old": old_values,
                    "new": values,
                    "before": old_values,
                    "after": values,
                    "added": added,
                    "removed": removed,
                    "severity": "High" if record_type in {"MX", "NS", "TXT"} else "Medium",
                    "owner": "DNS",
                })
        old_status = previous_domain.get("website", {}).get("status")
        new_status = current_domain.get("website", {}).get("status")
        if old_status != new_status:
            changes.append({
                "id": stable_id(domain, "status", old_status, new_status),
                "domain": domain,
                "category": "Website",
                "type": "HTTP status",
                "changeType": "website_status_changed",
                "old": old_status,
                "new": new_status,
                "before": old_status,
                "after": new_status,
                "severity": "Medium",
                "owner": "Website",
            })
        old_headers = previous_domain.get("website", {}).get("securityHeaders", {})
        new_headers = current_domain.get("website", {}).get("securityHeaders", {})
        for header, old_value in old_headers.items():
            if old_value and not new_headers.get(header):
                changes.append({
                    "id": stable_id(domain, "header_removed", header),
                    "domain": domain,
                    "category": "Website",
                    "type": header,
                    "changeType": "header_disappeared",
                    "before": old_value,
                    "after": None,
                    "severity": "High",
                    "owner": "Website",
                })
        old_vendors = {vendor.get("name") for vendor in previous_domain.get("website", {}).get("vendors", [])}
        new_vendors = {vendor.get("name") for vendor in current_domain.get("website", {}).get("vendors", [])}
        for vendor in sorted(new_vendors - old_vendors):
            changes.append({
                "id": stable_id(domain, "vendor_added", vendor),
                "domain": domain,
                "category": "Vendor",
                "type": "New vendor",
                "changeType": "new_vendor_added",
                "before": None,
                "after": vendor,
                "severity": "Medium",
                "owner": "Vendor",
            })
        for vendor in sorted(old_vendors - new_vendors):
            changes.append({
                "id": stable_id(domain, "vendor_removed", vendor),
                "domain": domain,
                "category": "Vendor",
                "type": "Vendor removed",
                "changeType": "vendor_removed",
                "before": vendor,
                "after": None,
                "severity": "Low",
                "owner": "Vendor",
            })
        old_nikto = set(previous_domain.get("website", {}).get("nikto", {}).get("findings", []))
        new_nikto = set(current_domain.get("website", {}).get("nikto", {}).get("findings", []))
        for finding in sorted(new_nikto - old_nikto):
            changes.append({
                "id": stable_id(domain, "nikto_added", finding),
                "domain": domain,
                "category": "Nikto",
                "type": "Finding appeared",
                "changeType": "nikto_finding_appeared",
                "before": None,
                "after": finding,
                "severity": "High",
                "owner": "Website",
            })
        for finding in sorted(old_nikto - new_nikto):
            changes.append({
                "id": stable_id(domain, "nikto_resolved", finding),
                "domain": domain,
                "category": "Nikto",
                "type": "Finding resolved",
                "changeType": "nikto_finding_resolved",
                "before": finding,
                "after": None,
                "severity": "Info",
                "owner": "Website",
            })
    return changes


def load_history() -> dict[str, Any]:
    if HISTORY_PATH.exists():
        with HISTORY_PATH.open() as fh:
            return json.load(fh)
    return {"domains": {}}


def save_history(domains: dict[str, Any]) -> None:
    HISTORY_PATH.write_text(json.dumps({"timestamp": utc_now(), "domains": domains}, indent=2))


def make_finding(domain: str, title: str, summary: str, impact: str, recommendation: str,
                 severity: str, owner: str, effort: str, confidence: str, evidence: Any) -> dict[str, Any]:
    return {
        "id": stable_id(domain, title, json.dumps(evidence, sort_keys=True, default=str)),
        "domain": domain,
        "title": title,
        "summary": summary,
        "impact": impact,
        "recommendation": recommendation,
        "severity": severity,
        "owner": owner,
        "effort": effort,
        "confidence": confidence,
        "evidence": evidence,
    }


def generate_findings(domains: dict[str, Any], changes: list[dict[str, Any]], is_first_run: bool) -> list[dict[str, Any]]:
    findings = []
    for domain, data in domains.items():
        website = data["website"]
        email = data["email"]
        for missing in website.get("securityAnalysis", {}).get("missing", []):
            severity = "High" if missing["name"] in {"HSTS", "CSP"} else "Medium"
            findings.append(make_finding(
                domain,
                f"{missing['name']} header is missing",
                f"{domain} does not publish the {missing['header']} header.",
                f"Missing {missing['name']} can reduce browser-side protection for visitors.",
                f"Add a {missing['header']} header at the web server, CDN, or hosting layer.",
                severity,
                "Website",
                "Low",
                "High",
                missing,
            ))
        for exposed in website.get("securityAnalysis", {}).get("exposedHeaders", []):
            findings.append(make_finding(
                domain,
                f"{exposed['header']} header is exposed",
                f"{domain} exposes {exposed['header']}: {exposed['value']}.",
                "Technology disclosure can help attackers fingerprint hosting or application components.",
                f"Review whether the {exposed['header']} header is needed and remove or reduce it when possible.",
                "Low",
                "Hosting",
                "Low",
                "Medium",
                exposed,
            ))
        if not email["spf"]["present"]:
            findings.append(make_finding(
                domain,
                "SPF record is missing",
                f"{domain} does not publish an SPF record.",
                "Attackers may have an easier time spoofing mail from this domain.",
                "Publish a TXT record beginning with v=spf1 that includes authorized mail senders.",
                "High" if email["mxPresent"] else "Medium",
                "Email",
                "Medium",
                "High",
                email["mxRecords"],
            ))
        if not email["dmarc"]["present"]:
            findings.append(make_finding(
                domain,
                "DMARC record is missing",
                f"{domain} does not publish a DMARC policy.",
                "Mailbox providers get less guidance on how to handle spoofed mail.",
                "Publish a _dmarc TXT record, starting with p=none for monitoring and moving toward quarantine or reject.",
                "High" if email["mxPresent"] else "Medium",
                "Email",
                "Medium",
                "High",
                email["dmarc"],
            ))
        elif email["dmarc"]["policy"] == "none":
            findings.append(make_finding(
                domain,
                "DMARC policy is monitoring only",
                f"{domain} has DMARC enabled with p=none.",
                "Spoofed messages may still be delivered because DMARC is not enforcing quarantine or rejection.",
                "After reviewing reports, move DMARC toward p=quarantine or p=reject.",
                "Medium",
                "Email",
                "Medium",
                "High",
                email["dmarc"],
            ))
        if not email["dkim"]["present"]:
            findings.append(make_finding(
                domain,
                "DKIM was not discovered",
                f"{domain} did not expose DKIM records for the common selectors checked.",
                "DKIM may still be configured with a custom selector, but undiscovered DKIM makes email authentication harder to verify externally.",
                "Confirm the active DKIM selector with the mail provider and publish or document the selector used for outbound mail.",
                "Medium" if email["mxPresent"] else "Low",
                "Email",
                "Medium",
                "Medium",
                email["dkim"],
            ))
        if email["spoofingRisk"] == "High":
            findings.append(make_finding(
                domain,
                "Email spoofing risk is high",
                f"{domain} is missing both SPF and DMARC.",
                "Customers, staff, or vendors may receive convincing spoofed messages that appear to come from this domain.",
                "Add SPF and DMARC records, then validate them with a follow-up scan.",
                "High",
                "Email",
                "Medium",
                "High",
                email,
            ))
        for vendor in website.get("vendors", []):
            if vendor.get("category") == "Unknown":
                findings.append(make_finding(
                    domain,
                    "Unknown third-party vendor observed",
                    f"{domain} loads content from {vendor['name']}, which is not categorized yet.",
                    "Unreviewed third-party scripts or assets can introduce availability, privacy, or security risk.",
                    "Validate the vendor purpose and categorize it as approved or remove it if unnecessary.",
                    "Medium",
                    "Vendor",
                    "Low",
                    "Medium",
                    vendor,
                ))
        nikto = website.get("nikto", {})
        for finding in nikto.get("findings", []):
            findings.append(make_finding(
                domain,
                "Nikto web exposure finding",
                finding,
                "Nikto identified a web exposure item that should be reviewed by the website or hosting owner.",
                "Review the finding, confirm whether it applies, and remediate or document acceptance.",
                "High",
                "Website",
                "Medium",
                "Medium",
                finding,
            ))
    if not is_first_run:
        for change in changes:
            if change["severity"] in {"Critical", "High", "Medium"}:
                findings.append(make_finding(
                    change["domain"],
                    change["type"] + " changed",
                    f"{change['domain']} had a {change['category']} change: {change.get('changeType', 'changed')}.",
                    "Unexpected external changes can indicate hosting, DNS, vendor, or security control drift.",
                    "Confirm whether this change was authorized. If not, investigate and restore the previous known-good state.",
                    change["severity"],
                    change["owner"],
                    "Low",
                    "High",
                    change,
                ))
    return sorted(findings, key=lambda finding: (-SEVERITY_RANK.get(finding["severity"], 0), finding["domain"], finding["title"]))


def build_scorecard(domains: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    def status_for(owner: str, high_threshold: int = 1) -> str:
        owner_findings = [finding for finding in findings if finding["owner"] == owner]
        if any(finding["severity"] in {"Critical", "High"} for finding in owner_findings):
            return "Action Needed"
        if len(owner_findings) >= high_threshold:
            return "Watch"
        return "Pass"

    nikto_findings = [finding for finding in findings if "Nikto" in finding["title"]]
    unknown_vendors = [finding for finding in findings if finding["owner"] == "Vendor"]
    email_statuses = [
        data.get("email", {}).get("health", {}).get("overall", "Watch")
        for data in domains.values()
    ]
    if "Action Needed" in email_statuses:
        email_status = "Action Needed"
    elif "Watch" in email_statuses:
        email_status = "Watch"
    else:
        email_status = "Pass"
    return [
        {"area": "DNS health", "status": "Action Needed" if any("MX" in f["title"] or "NS" in f["title"] for f in findings) else "Pass", "summary": "DNS records are monitored for additions, removals, and sensitive changes."},
        {"area": "Website security headers", "status": status_for("Website"), "summary": "Browser security headers and exposed hosting headers are checked."},
        {"area": "Email authentication", "status": email_status, "summary": "SPF, DKIM, DMARC, MX provider, and spoofing risk are reviewed."},
        {"area": "Vendor exposure", "status": "Watch" if unknown_vendors else "Pass", "summary": "Third-party hosts are categorized and unknown vendors are flagged."},
        {"area": "External vulnerability scan", "status": "Action Needed" if nikto_findings else "Pass", "summary": "Nikto findings are promoted into customer-readable findings."},
    ]


def build_remediation(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    tasks = []
    for finding in findings:
        tasks.append({
            "id": stable_id("task", finding["id"]),
            "domain": finding["domain"],
            "task": finding["recommendation"],
            "sourceFinding": finding["id"],
            "severity": finding["severity"],
            "owner": finding["owner"],
            "effort": finding["effort"],
            "evidence": finding["evidence"],
        })
    return tasks


def build_summary(domains: dict[str, Any], changes: list[dict[str, Any]], report_name: str) -> dict[str, Any]:
    history = load_history()
    is_first_run = not bool(history.get("domains"))
    vendor_counts = {category: 0 for category in ("Analytics", "Advertising", "Social", "Fonts", "Payment", "Marketing", "CDN", "Libraries", "Unknown")}
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
            vendor_counts[vendor["category"]] = vendor_counts.get(vendor["category"], 0) + 1
            key = (vendor["name"], vendor["category"])
            vendors_table.setdefault(key, {"name": vendor["name"], "type": vendor["category"], "category": vendor["category"], "riskLabel": vendor["riskLabel"], "reason": vendor["reason"], "sites": set(), "status": "observed"})
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

    findings = generate_findings(domains, changes, is_first_run)
    scorecard = build_scorecard(domains, findings)
    remediation = build_remediation(findings)
    effective_changes = [] if is_first_run else changes

    return {
        "timestamp": utc_now(),
        "mode": "baseline" if is_first_run else "monitoring",
        "isFirstRun": is_first_run,
        "baselineMessage": "This is your baseline. Future scans will highlight changes." if is_first_run else "",
        "totalDomains": total_domains,
        "averageSecurityScore": security_score,
        "contentChanges": sum(1 for change in effective_changes if change["category"] == "Website"),
        "dnsChanges": sum(1 for change in effective_changes if change["category"] == "DNS"),
        "newVendors": sum(len(data["website"].get("vendors", [])) for data in domains.values()),
        "criticalChanges": [
            f"{change['domain']} {change['type']}" for change in effective_changes
            if change["category"] == "DNS" and change["type"] in {"MX", "NS", "TXT"}
        ],
        "scorecard": scorecard,
        "findings": findings,
        "remediation": remediation,
        "changes": effective_changes,
        "vendorTypes": vendor_counts,
        "securityHeaders": header_counts,
        "recentChanges": [] if is_first_run else recent_changes,
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
    scorecard_rows = []
    for card in summary.get("scorecard", []):
        scorecard_rows.append(
            "<tr>"
            f"<td>{html.escape(card['area'])}</td>"
            f"<td>{html.escape(card['status'])}</td>"
            f"<td>{html.escape(card['summary'])}</td>"
            "</tr>"
        )
    finding_rows = []
    for finding in summary.get("findings", [])[:25]:
        finding_rows.append(
            "<tr>"
            f"<td>{html.escape(finding['severity'])}</td>"
            f"<td>{html.escape(finding['title'])}<br><small>{html.escape(finding['summary'])}</small></td>"
            f"<td>{html.escape(finding['impact'])}</td>"
            f"<td>{html.escape(finding['recommendation'])}</td>"
            f"<td>{html.escape(finding['owner'])}</td>"
            "</tr>"
        )
    remediation_rows = []
    for task in summary.get("remediation", [])[:25]:
        remediation_rows.append(
            "<tr>"
            f"<td>{html.escape(task['severity'])}</td>"
            f"<td>{html.escape(task['owner'])}</td>"
            f"<td>{html.escape(task['effort'])}</td>"
            f"<td>{html.escape(task['task'])}</td>"
            "</tr>"
        )
    domain_rows = []
    for site in summary["sites"]:
        domain = site["domain"]
        data = summary["domains"][domain]
        domain_rows.append(
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
    body {{ margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f7f6f0; color: #3d3926; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 42px 24px; }}
    h1 {{ font-size: 42px; margin: 0 0 10px; }}
    h2 {{ margin-top: 34px; }}
    .lede {{ color: #5f5532; margin-bottom: 28px; }}
    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 28px; }}
    .stat, table {{ background: rgba(255,255,255,.72); border: 1px solid rgba(95,85,50,.16); border-radius: 8px; }}
    .stat {{ padding: 18px; }}
    .label {{ color: #7d703c; font-size: 12px; text-transform: uppercase; letter-spacing: .12em; }}
    .value {{ font-size: 30px; font-weight: 800; margin-top: 6px; }}
    table {{ width: 100%; border-collapse: collapse; overflow: hidden; }}
    th, td {{ padding: 13px 14px; border-bottom: 1px solid rgba(95,85,50,.14); text-align: left; vertical-align: top; }}
    th {{ color: #5f5532; font-size: 12px; text-transform: uppercase; letter-spacing: .08em; background: rgba(238,236,216,.68); }}
    small {{ color: #5f5532; }}
  </style>
</head>
<body>
  <main>
    <h1>External Domain Baseline</h1>
    <p class="lede">Generated {html.escape(summary['timestamp'])}. Public-facing DNS, website, vendor, and email exposure baseline.</p>
    {f"<p><strong>{html.escape(summary['baselineMessage'])}</strong></p>" if summary.get('baselineMessage') else ""}
    <section class="stats">
      <div class="stat"><div class="label">Domains</div><div class="value">{summary['totalDomains']}</div></div>
      <div class="stat"><div class="label">Security Score</div><div class="value">{summary['averageSecurityScore']}%</div></div>
      <div class="stat"><div class="label">DNS Changes</div><div class="value">{summary['dnsChanges']}</div></div>
      <div class="stat"><div class="label">Vendors</div><div class="value">{summary['newVendors']}</div></div>
    </section>
    <h2>Customer Scorecard</h2>
    <table><thead><tr><th>Area</th><th>Status</th><th>Summary</th></tr></thead><tbody>{''.join(scorecard_rows)}</tbody></table>
    <h2>Plain-English Findings</h2>
    <table><thead><tr><th>Severity</th><th>Finding</th><th>Impact</th><th>Recommended Fix</th><th>Owner</th></tr></thead><tbody>{''.join(finding_rows) or '<tr><td colspan="5">No findings.</td></tr>'}</tbody></table>
    <h2>Remediation Checklist</h2>
    <table><thead><tr><th>Severity</th><th>Owner</th><th>Effort</th><th>Task</th></tr></thead><tbody>{''.join(remediation_rows) or '<tr><td colspan="4">No remediation tasks.</td></tr>'}</tbody></table>
    <h2>Domain Evidence</h2>
    <table>
      <thead><tr><th>Domain</th><th>Status</th><th>DNS Changes</th><th>Vendors</th><th>Public Emails</th><th>MX Records</th></tr></thead>
      <tbody>{''.join(domain_rows)}</tbody>
    </table>
  </main>
</body>
</html>
""")


def send_watch_alerts(summary: dict[str, Any], report_name: str) -> None:
    high_items = [
        finding for finding in summary.get("findings", [])
        if finding.get("severity") in {"Critical", "High"}
    ]
    high_items.extend([
        change for change in summary.get("changes", [])
        if change.get("severity") in {"Critical", "High"}
    ])
    if not high_items:
        return

    lines = [
        "External Domain Baseline alert",
        f"Generated: {summary['timestamp']}",
        f"Report: domain_reports/{report_name}",
        "",
        "High priority items:",
    ]
    for item in high_items[:10]:
        title = item.get("title") or f"{item.get('domain')} {item.get('type')}"
        lines.append(f"- {title}")
    message = "\n".join(lines)

    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    if webhook:
        try:
            request = Request(webhook, data=json.dumps({"text": message}).encode("utf-8"), headers={"Content-Type": "application/json"})
            urlopen(request, timeout=10).read()
        except (OSError, URLError, TimeoutError) as exc:
            print(f"Slack alert failed: {exc}", file=sys.stderr)

    smtp_host = os.environ.get("SMTP_HOST")
    smtp_to = os.environ.get("SMTP_TO")
    smtp_from = os.environ.get("SMTP_FROM", "external-baseline@localhost")
    if smtp_host and smtp_to:
        try:
            email = EmailMessage()
            email["Subject"] = "External Domain Baseline alert"
            email["From"] = smtp_from
            email["To"] = smtp_to
            email.set_content(message)
            with smtplib.SMTP(smtp_host, int(os.environ.get("SMTP_PORT", "25")), timeout=10) as smtp:
                if os.environ.get("SMTP_USERNAME"):
                    smtp.starttls()
                    smtp.login(os.environ["SMTP_USERNAME"], os.environ.get("SMTP_PASSWORD", ""))
                smtp.send_message(email)
        except (OSError, smtplib.SMTPException) as exc:
            print(f"Email alert failed: {exc}", file=sys.stderr)


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
    send_watch_alerts(summary, report_name)
    save_history(current)
    print(f"Wrote {SUMMARY_PATH}")
    print(f"Wrote {REPORTS_DIR / report_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
