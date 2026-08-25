# M0 COH-E01 design-freeze approval packet — 2026-08-25

| Field | Value |
|---|---|
| Parent issue | COH-E01 / CYB-5 |
| Leaf issues | COH-E01-01 / CYB-29; COH-E01-02 / CYB-31; COH-E01-03 / CYB-30; COH-E01-04 / CYB-34 |
| Source checkpoint | `8b0ed553d2e0c7dfb727025a8a73fbee8f7de8f5` |
| Verification date | 2026-08-25 |
| Status | Technically verified; explicit human decisions pending |
| Data classification | Internal product-governance metadata; no credentials or case evidence |

This packet supersedes the local-era evidence report dated 2026-08-19. The
reviewed document bytes remain unchanged, but the repository now has a published
Git revision, reproducible trace inputs, and clean promotable baseline CI.

Approval of this packet freezes product and security design decisions. It does
not activate policy, grant runtime authority, qualify a production release, or
approve a T4 action.

## Reviewed artifacts

| Issue | Artifact | Lines | SHA-256 |
|---|---|---:|---|
| CYB-29 | `docs/design/product-contract.md` | 173 | `c6ef179584af674305f31470f58935c90312b4990588918fa8c51396effb35eb` |
| CYB-31 | `docs/adr/0001-trust-boundaries.md` | 469 | `5541f0eebaea287ec2ca7e695670205757b55707c1733291f3222d764ccb075c` |
| CYB-31 | `docs/adr/0001-trust-boundaries-verification.md` | 65 | `49b97a638d42feb6c36a0daf3a9916f125da54543642d773d78d68d3a45e2da2` |
| CYB-30 | `docs/security/action-tier-decision-table.md` | 223 | `0628b6be9824bd0c28d6b3254bc3132cd14f0dffa4df9452f6c482c0cfde9a2b` |
| CYB-34 | `docs/design/platform-support-matrix.md` | 111 | `151ce95f9783493edfeafcf840bb55214660c30fa732d319e0335f537f785570` |

## Technical verification result

| Check | Current result |
|---|---|
| PRD/issue trace | 187 requirements defined and referenced; four exact E01 mappings; zero missing or unexpected |
| PRD trace negative suite | Bad mapping, missing heading, and bad trace are denied |
| Design semantics | 10 workflows, 6 platforms, 3 connectivity profiles, 11 trust boundaries, 5 action tiers, 1 Mermaid graph, zero ambiguous staffing phrases |
| Design negative suite | Missing tier, boundary, Windows support, or capability control; ambiguous staffing; false status; and Docker-required wording are denied |
| Network links | 15 references, 5 unique external URLs, zero failures |
| File-size policy | Pass; no hard or script limit violation |
| Clean baseline CI | 18/18 stages pass at `8b0ed55`; clean revision and promotable result |

Baseline CI includes format, file size, workflow policy, worktree and history
secret scans, architecture, quality-contract tests, vet, static analysis, unit,
race, fuzz seeds, license, dependency/offline vulnerability scan, SBOM, supply
chain, evidence-secret scan, and provenance.

## Decision summary

### CYB-29 — product scope

- The solo analyst is the primary persona; approver, administrator, auditor,
  responder, threat hunter, vulnerability analyst, detection engineer, and
  platform operator responsibilities are explicit.
- Supported workflows and measurable outcomes are defined with explicit
  non-goals and no silent promise of autonomous authority.
- Native-first, Docker-optional operation and the prohibition on solo T4 are
  product constraints.

Required decisions: Product Owner approves scope/personas/outcomes; Security
confirms the product promise does not weaken authority controls; Requirements
confirms exact `FR-001`, `FR-005`, and `NFR-030` trace.

### CYB-31 — architecture and trust boundaries

- The model is an untrusted planner and cannot authorize, lease credentials,
  dispatch actions, or write authoritative evidence directly.
- Process, data, credential, model, connector, remote-system, validator, runner,
  audit, and T4 isolation boundaries are explicit.
- Tool and connector authority crosses only the broker with fail-closed audit,
  policy, approval, lease, confirmation, cancellation, and recovery behavior.

Required decisions: Product Owner accepts operational consequences; Security
Architecture approves the boundary/control model; Implementation confirms the
architecture is implementable without hidden bypasses.

### CYB-30 — T0–T4 action controls

- Unknown or ambiguous actions deny. Runtime policy may narrow a signed
  capability ceiling but cannot expand it.
- T0 through T4 define approvals, isolation, evidence, rollback, retry,
  uncertainty, cancellation, and E-stop behavior.
- T4 requires two distinct eligible non-requestor approvers, signed in-window
  ROE, safety watch, rehearsed rollback, and a dedicated isolated execution zone.

Required decisions: Product accepts workflow/staffing consequences; Security
Architecture approves tier semantics and separation; Implementation confirms
the controls can be enforced and evidenced.

### CYB-34 — platform and support claims

- Tier 1 native macOS/Linux/DGX, optional Compose profiles, and best-effort
  Docker-only Windows are distinguished without claiming equivalence.
- Connected, restricted-connected, and air-gapped modes state qualification and
  update limitations.
- Docker cannot redefine native APIs or become a hidden prerequisite. T4 never
  runs in the shared workstation or ordinary Compose environment.

Required decisions after CYB-29/30/31 approval: Product approves support claims;
Security Architecture approves isolation/connectivity limitations;
Implementation accepts qualification and documentation obligations.

## Approval-record requirements

Each approval recorded in Linear must include:

1. reviewer identity and accountable role;
2. decision: `approve`, `approve with named follow-up`, or `reject`;
3. exact scope: issue identifiers, source checkpoint, and artifact digests;
4. confirmation that alternatives, non-goals, migration/compatibility impact,
   invalid/denial/timeout/cancellation/recovery behavior, and trace were reviewed;
5. unresolved findings or an explicit statement that none remain; and
6. decision timestamp.

An approval with an unresolved blocking finding does not satisfy the Done gate.
Silence, an issue assignment, or this technical report is not approval.

## Required approval checklist

### CYB-29

- [ ] Product Owner approval
- [ ] Security reviewer approval
- [ ] Requirements approval

### CYB-31

- [ ] Product Owner approval
- [ ] Security Architecture approval
- [ ] Implementation approval

### CYB-30

- [ ] Product approval
- [ ] Security Architecture approval
- [ ] Implementation approval

### CYB-34

- [ ] CYB-29, CYB-30, and CYB-31 are Done
- [ ] Product Owner approval
- [ ] Security Architecture approval
- [ ] Implementation approval

### CYB-5 integration

- [ ] All four children are Done
- [ ] Product promises/non-goals retain exact PRD trace or explicit exclusions
- [ ] Product, Security Architecture, and Implementation approve the complete packet

## Verification commands

```sh
scripts/verify_prd_trace.sh
internal/verify/test_verify_prd_trace.sh
scripts/verify_design_decisions.sh
internal/verify/test_verify_design_decisions.sh
scripts/check_file_sizes.sh
scripts/check_markdown_links.sh --network \
  docs/design/product-contract.md \
  docs/adr/0001-trust-boundaries.md \
  docs/adr/0001-trust-boundaries-verification.md \
  docs/security/action-tier-decision-table.md \
  docs/design/platform-support-matrix.md
scripts/run_ci_quality.sh baseline
```

The checksum ledger `M0-E01-artifacts-2026-08-25.sha256` binds the review inputs
and this packet. It excludes itself to avoid a recursive digest.

