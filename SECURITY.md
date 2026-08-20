# Security Policy

## Project status

COH is in early, pre-release development. No released version currently receives
security support, and the repository is not yet suitable for production use.
Security boundaries and guarantees described in design documents remain proposed
until their implementing issue and verification evidence are complete.

## Reporting a vulnerability

Do not disclose suspected vulnerabilities in a public issue, discussion, pull
request, commit, or log. Use GitHub's private vulnerability reporting form for
this repository:

<https://github.com/ArronJablonowski/COH/security/advisories/new>

If that form is unavailable, open a minimal public issue asking the maintainers
to provide a private reporting channel. Do not include vulnerability details,
credentials, exploit payloads, customer data, security evidence, or target
information in that issue.

Include the affected revision or release, deployment mode, prerequisites,
reproduction steps, observed impact, and a suggested mitigation when it is safe
to do so. Redact secrets and third-party data. Reports are assessed as project
capacity permits; no response or remediation timeline is guaranteed during the
pre-release phase.

Only test systems and data that you own or are explicitly authorized to assess.
This policy does not authorize testing third-party services or production
deployments.

## Public hardening work

General hardening ideas that do not reveal an exploitable condition may be filed
as public issues. Security fixes should not be published until the associated
private report has been assessed and a coordinated disclosure decision has been
made.
