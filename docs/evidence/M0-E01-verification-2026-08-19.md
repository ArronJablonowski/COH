# M0 E01 verification report — 2026-08-19

| Field | Value |
|---|---|
| Issues | `COH-E01-01` / CYB-29; `COH-E01-02` / CYB-31; `COH-E01-03` / CYB-30 |
| Requirements | `FR-001`, `FR-005`, `NFR-030`; `SEC-001`, `SEC-002`, `SEC-017`, `SEC-026`; `SEC-003`, `SEC-005`, `SEC-006`, `SEC-007`, `SEC-008` |
| Verification status | Automated and AI technical review complete; human approval pending |
| Repository | `/Volumes/Untitled/Codex/COH` |
| Data classification | Internal engineering metadata; no case data, credentials, or customer evidence |
| Migration impact | None; documentation and bootstrap architecture contract only |

This report records reproducible evidence for the first three M0 decisions. It is
not a human approval and does not authorize a runtime action.

## Reviewed artifacts

| Artifact | Lines | SHA-256 |
|---|---:|---|
| `docs/design/product-contract.md` | 173 | `c6ef179584af674305f31470f58935c90312b4990588918fa8c51396effb35eb` |
| `docs/adr/0001-trust-boundaries.md` | 469 | `5541f0eebaea287ec2ca7e695670205757b55707c1733291f3222d764ccb075c` |
| `docs/adr/0001-trust-boundaries-verification.md` | 65 | `49b97a638d42feb6c36a0daf3a9916f125da54543642d773d78d68d3a45e2da2` |
| `docs/security/action-tier-decision-table.md` | 223 | `0628b6be9824bd0c28d6b3254bc3132cd14f0dffa4df9452f6c482c0cfde9a2b` |
| `scripts/verify_prd_trace.sh` | 157 | `83fd9e667cda0b028ebfe502f7fb73f4b26c8a4ca8ba383f5ddd1281c2dcc36e` |
| `internal/verify/test_verify_prd_trace.sh` | 68 | `1f7e95d63cee269d7af92286de7443dcac8eece7c7b9ec62dfcf68b376ad9255` |
| `scripts/verify_design_decisions.sh` | 135 | `8bc0d2bb2c16b4e146732997e35d73f07084bc4fbd94e01be5ff641b54a941b4` |
| `internal/verify/test_verify_design_decisions.sh` | 61 | `1e3647d1a0d41bf0bc27fcc7799746d8cb97b70367025394558b3582e1abc70b` |

## Automated results

| Check | Command or tool | Result |
|---|---|---|
| PRD and issue trace | `scripts/verify_prd_trace.sh` | 187 defined, 187 referenced; exact mappings for all three issues; zero missing/unexpected |
| Trace negative fixtures | `internal/verify/test_verify_prd_trace.sh` | 1 positive and 3 negative cases passed: bad mapping, missing heading, wrong trace ID |
| Decision semantics | `scripts/verify_design_decisions.sh` | 10 workflows, 11 catalogue boundaries, 5 tiers, 1 Mermaid graph, 0 ambiguous staffing phrases |
| Decision negative fixtures | `internal/verify/test_verify_design_decisions.sh` | 1 positive and 5 negative cases passed: missing T4, missing validator boundary, ambiguous T4 staffing, false approval status, missing exported-capability control |
| Broker-only architecture | `scripts/test_go_contract.sh` | Go 1.26.7 gofmt, vet, unit, race, canonical-contract, and graph checks passed; workflow/provider/command/transport connector bypass fixtures denied |
| Mermaid parse/render | `mmdc` 11.16.0 | ADR graph rendered successfully to SVG; SHA-256 `727ff70420d3dd549c1245514228b6d371f1a585180ce5834369314fbea515cf` |
| Links | `scripts/check_markdown_links.sh --network ...` | 28 references, 6 unique external URLs, 0 failures |
| File sizes | `scripts/check_file_sizes.sh` | 60 files checked, 0 failures; only canonical PRD/research crossed the 500-line warning threshold |
| Secrets | `gitleaks` 8.30.1 `dir . --redact` | Approximately 8.06 MB scanned; no leaks found |
| License/dependencies | `LICENSE`; `go list -m all` | Apache-2.0 present; Go module has no external requirements |
| Manifest integrity | `jq -e . work/COH-Linear-Manifest.json` | Valid JSON; all 187 PRD requirements remain covered |

The Go and npm caches, Go toolchain, Puppeteer browser, and generated Mermaid
output were stored under `/Volumes/Untitled/Codex`, not the internal drive.

## Failure, cancellation, and recovery coverage

- Invalid, missing, unknown, duplicated, unsupported, and policy-widening contract
  inputs are rejected with typed errors and without changing source or policy.
- Missing tiers, boundaries, trace IDs, required headings, and ambiguous T4 staffing
  are rejected by negative fixtures.
- A cancelled architecture evaluation returns a cancellation error; rerunning the
  same immutable graph succeeds without recovery state.
- A denied graph can be corrected and rerun; denial never changes the contract.
- The decision records preserve post-dispatch timeout as `uncertain`, prohibit
  blind retry, retain provenance, and make cancellation/E-stop independent of the
  model.

## Review history and remediation

Independent AI technical review identified and verified remediation of:

1. ambiguous T4 staffing language, now explicitly requiring two distinct eligible
   non-requestor approvers and normally three humans for a human-requested action;
2. approval metadata that overstated sign-off, now consistently marked Ready for
   approval;
3. the provider gateway and model runtime sharing one trust zone, now split;
4. an overbroad broker statement, now limited to tool actions, connector access,
   validators, runners, and external side effects;
5. a missing remote security-system side of the connector boundary, now explicit;
6. direct workflow connector/policy ports, now replaced by a narrow
   `ActionAuthority` port; and
7. missing broker-bypass fixtures, now covering workflow, provider, command, and
   remote-facing transport paths; and
8. an exported broker dependency bundle that leaked a connector capability through
   the composition API, now made private and guarded by an AST API-surface test.

Independent AI technical peer sign-off applies to the exact document digests in
this report, including the strengthened exported-capability companion contract.
It does not replace the human Product Owner, Security Architecture, Requirement,
or Implementation approvals required by the records.

## Acceptance status

### CYB-29 / COH-E01-01

- [x] Persona, workflows, measurable outcomes, and explicit non-goals are present.
- [x] Decisions, alternatives, owners, traceability, status, and links are verified.
- [x] Invalid/denial/timeout/cancellation/recovery behavior preserves authority and provenance.
- [x] Applicable automated positive/negative, secret, license, and size gates pass.
- [ ] Human Product Owner, Security, and Requirement sign-off on the attached artifact.

### CYB-31 / COH-E01-02

- [x] Process, data, credential, model, connector, runner, validator, remote-system, and T4 boundaries are explicit.
- [x] Decisions, alternatives, owners, traceability, status, and links are verified.
- [x] Invalid/denial/timeout/cancellation/recovery behavior preserves authority and provenance.
- [x] Mermaid, Go 1.26.7, race, and broker-bypass architecture gates pass.
- [ ] Human Product Owner, Security Architecture, and Implementation sign-off on both ADR files.

### CYB-30 / COH-E01-03

- [x] T0–T4 map authorization, approval, isolation, evidence, rollback, retry, uncertainty, cancellation, recovery, and E-stop; unknown actions deny.
- [x] Decisions, alternatives, owners, traceability, status, and links are verified.
- [x] Invalid/denial/timeout/cancellation/recovery behavior preserves authority and provenance.
- [x] Applicable automated positive/negative, secret, license, and size gates pass.
- [ ] Human Product, Security Architecture, and Implementation sign-off on the attached artifact.

The three issues remain **In Progress** until the unchecked human approval gates
are recorded. Because this repository has no approved Git `HEAD` yet, the complete
new artifacts and their digests are supplied for review instead of claiming an
approved Git diff that does not exist.
