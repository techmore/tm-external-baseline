# Product Issues

This roadmap turns the external baseline scanner into a customer-facing product. The priority is helping customers understand what changed, why it matters, and what to do next.

## P0 - Plain-English Findings

**Goal:** Convert raw scanner output into customer-readable findings.

**User value:** Customers should not need to understand DNS, headers, Nikto, or TXT syntax to understand risk.

**Acceptance criteria:**

- Every finding includes:
  - What changed or was observed
  - Why it matters
  - Business or security impact
  - Recommended fix
  - Confidence level
- Missing headers, DNS changes, vendor changes, Nikto findings, and email security gaps all use the same finding shape.
- Dashboard displays findings before raw evidence.

**Implementation notes:**

- Add a `findings` array to `latest_summary.json`.
- Use fields: `title`, `summary`, `impact`, `recommendation`, `severity`, `owner`, `effort`, `confidence`, `evidence`.
- Example: `This site does not publish a Content-Security-Policy header, which increases browser-side injection risk.`

## P0 - Customer Scorecard

**Goal:** Replace raw percentages as the primary status with simple health labels.

**User value:** Customers can quickly answer, “Are we okay?”

**Acceptance criteria:**

- Top of dashboard shows five scorecard areas:
  - DNS health
  - Website security headers
  - Email security
  - Vendor exposure
  - External vulnerability scan
- Each area uses one of:
  - `Pass`
  - `Watch`
  - `Action Needed`
- Each scorecard item links to relevant findings.

**Implementation notes:**

- Add `scorecard` to `latest_summary.json`.
- Keep numeric detail available, but make labels the first thing customers see.

## P0 - First-Run Baseline Explanation

**Goal:** Make first-run behavior understandable.

**User value:** Customers will not panic when the first scan marks everything as new.

**Acceptance criteria:**

- First run is detected when no history exists.
- Dashboard shows: `This is your baseline. Future scans will highlight changes.`
- First-run findings are labeled as baseline observations, not incidents.
- Subsequent scans switch to change monitoring mode.

**Implementation notes:**

- Add `isFirstRun` and `mode` to `latest_summary.json`.
- Avoid showing first-run DNS records as critical changes.

## P1 - Before / After Change Timeline

**Goal:** Show exactly what changed between scans.

**User value:** Customers can distinguish expected changes from suspicious changes.

**Acceptance criteria:**

- Timeline supports:
  - New DNS record
  - Removed DNS record
  - Header disappeared
  - New vendor appeared
  - Vendor removed
  - MX changed
  - Nikto finding appeared
  - Nikto finding resolved
- Each timeline item includes before and after evidence.
- High-risk timeline items are promoted into findings.

**Implementation notes:**

- Store normalized snapshots in `external_domain_history.json`.
- Add `changes` with `before`, `after`, `changeType`, `severity`, and `owner`.

## P1 - Email Security Checks

**Goal:** Expand email reporting beyond public email enumeration.

**User value:** Email spoofing risk is understandable and valuable for customers, MSPs, schools, and nonprofits.

**Acceptance criteria:**

- Report includes:
  - SPF present and valid
  - DMARC present
  - DMARC policy strength: `none`, `quarantine`, `reject`
  - DKIM selector discovery where possible
  - MX provider identification
  - Spoofing risk summary
- Weak or missing SPF/DMARC generates plain-English findings.

**Implementation notes:**

- Query `_dmarc.<domain>` TXT.
- Parse SPF from root TXT records.
- Try common DKIM selectors: `google`, `selector1`, `selector2`, `default`, `k1`, `mail`.
- Identify MX providers by host patterns such as Google Workspace, Microsoft 365, Proofpoint, Mimecast, Fastmail, Zoho, and Hover.

## P1 - Remediation Checklist

**Goal:** Turn scanner output into work customers can complete.

**User value:** Customers know what to fix and who should fix it.

**Acceptance criteria:**

- Each actionable finding creates a checklist task.
- Tasks include:
  - Owner
  - Effort
  - Severity
  - Suggested fix
  - Evidence
- Dashboard has a remediation section.

**Example tasks:**

- Add HSTS
- Add DMARC record
- Review exposed server header
- Validate third-party script
- Confirm MX change was authorized

**Implementation notes:**

- Generate `remediation` array from findings.
- Make tasks stable across runs using deterministic IDs.

## P1 - Severity, Ownership, and Effort

**Goal:** Make findings operational.

**User value:** Customers can route work to the right person.

**Acceptance criteria:**

- Findings include:
  - Severity: `Critical`, `High`, `Medium`, `Low`, `Info`
  - Owner: `DNS`, `Website`, `Email`, `Vendor`, `Hosting`
  - Effort: `Low`, `Medium`, `High`
- Dashboard findings table includes these columns.
- Report export includes these fields.

**Implementation notes:**

- Add a small rules engine that maps evidence to severity, owner, and effort.
- Keep defaults conservative and explainable.

## P2 - Vendor / Third-Party Risk Labels

**Goal:** Categorize third-party hosts in a useful way.

**User value:** Customers understand what each external dependency likely does.

**Acceptance criteria:**

- Vendor labels include:
  - CDN
  - Analytics
  - Fonts
  - Payment
  - Marketing
  - Social
  - Unknown
- New vendor detection creates timeline events.
- Unknown vendors generate `Watch` scorecard state.

**Implementation notes:**

- Expand `VENDOR_PATTERNS`.
- Add `riskLabel`, `category`, and `reason`.
- Start with deterministic pattern matching before considering external enrichment.

## P2 - Customer-Friendly Report Export

**Goal:** Make reports easy to share with leadership, customers, and auditors.

**User value:** MSPs and teams can send an executive report without explaining raw scanner output.

**Acceptance criteria:**

- Dashboard has a `Download HTML Report` button.
- Report includes:
  - Executive summary
  - Scorecard
  - Top findings
  - Remediation checklist
  - Technical evidence appendix
- PDF export is documented or implemented.

**Implementation notes:**

- HTML export already exists; improve it with the same scorecard/findings model.
- PDF can be browser print-to-PDF first, automated rendering later.

## P2 - Watch Mode Alerts

**Goal:** Turn daily monitoring into useful alerts.

**User value:** Customers hear about meaningful changes without reading every report.

**Acceptance criteria:**

- Scheduled scan remains available through `scheduled.sh`.
- High-risk changes can alert through:
  - Email
  - Slack webhook
  - Weekly summary report
- Alerts include plain-English summary and link/path to report.

**Implementation notes:**

- Add optional `.env` config:
  - `SLACK_WEBHOOK_URL`
  - `SMTP_HOST`
  - `SMTP_FROM`
  - `SMTP_TO`
- Keep alerts disabled by default.

## Suggested Build Order

1. First-run baseline explanation
2. Findings data model
3. Customer scorecard
4. Email security checks
5. Remediation checklist
6. Before/after timeline
7. Vendor risk labels
8. HTML report export polish
9. Watch mode alerts
