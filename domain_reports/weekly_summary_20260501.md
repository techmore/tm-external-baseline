# External Domain Baseline Weekly Summary

Generated: 2026-05-01T03:05:45Z
Latest scan: 2026-05-01T03:05:38Z
Domains monitored: 1

## Scorecard
- DNS health: Pass - DNS records are monitored for additions, removals, and sensitive changes.
- Website security headers: Action Needed - Browser security headers and exposed hosting headers are checked.
- Email authentication: Action Needed - SPF, DKIM, DMARC, MX provider, and spoofing risk are reviewed.
- Vendor exposure: Watch - Third-party hosts are categorized and unknown vendors are flagged.
- External vulnerability scan: Pass - Nikto findings are promoted into customer-readable findings.

## Top Findings
- [High] CSP header is missing (cybersecuritypilot.org)
- [High] DMARC record is missing (cybersecuritypilot.org)
- [High] Email spoofing risk is high (cybersecuritypilot.org)
- [High] HSTS header is missing (cybersecuritypilot.org)
- [High] SPF record is missing (cybersecuritypilot.org)
- [Medium] Referrer-Policy header is missing (cybersecuritypilot.org)
- [Medium] Unknown third-party vendor observed (cybersecuritypilot.org)
- [Medium] Unknown third-party vendor observed (cybersecuritypilot.org)
- [Medium] Unknown third-party vendor observed (cybersecuritypilot.org)
- [Medium] XCTO header is missing (cybersecuritypilot.org)

## Remediation
- [High] Add a content-security-policy header at the web server, CDN, or hosting layer.
- [High] Publish a _dmarc TXT record, starting with p=none for monitoring and moving toward quarantine or reject.
- [High] Add SPF and DMARC records, then validate them with a follow-up scan.
- [High] Add a strict-transport-security header at the web server, CDN, or hosting layer.
- [High] Publish a TXT record beginning with v=spf1 that includes authorized mail senders.
- [Medium] Add a referrer-policy header at the web server, CDN, or hosting layer.
- [Medium] Validate the vendor purpose and categorize it as approved or remove it if unnecessary.
- [Medium] Validate the vendor purpose and categorize it as approved or remove it if unnecessary.
- [Medium] Validate the vendor purpose and categorize it as approved or remove it if unnecessary.
- [Medium] Add a x-content-type-options header at the web server, CDN, or hosting layer.
