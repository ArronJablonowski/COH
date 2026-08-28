# CYB-105 signed pySigma helper qualification report

| Field | Value |
|---|---|
| Issue | CYB-105 / COH-E15-01 |
| Requirements | FR-055, FR-056, SEC-019 |
| Source checkpoint | `c597fe4ca9feeea31d4cad600c7186a963b9280e` |
| Candidate RID | `osx-arm64` |
| Artifact | `sha256:2fc6ccdce6b870e2e6b681e88da6738377ce79ce8dd1f5c3b2d224e65fb54e0c` |
| Qualification | Candidate; blocked by CYB-187 license disposition |
| Release eligible | No |

## Outcome

The credentialless pySigma helper, signed native-admission boundary, strict Go
adapter, adversarial corpus, and native-validation handoff are implemented.
Tasks 1–6 of CYB-105 are complete. The selected runtime closure has zero current
OSV findings after removal of DiskCache 5.6.3 and the unused remote MITRE data
modules. The exact source checkpoint passed all 18 repository-wide baseline CI
stages with a clean worktree.

CYB-105 is not complete and this packet is not release approval. CYB-187 blocks
the Python license gate pending an authorized disposition for PyInstaller's
bootloader exception and the LGPL pySigma/backend components. The deterministic
Ed25519 key in tests proves only the signed-registry path and is never release
authority. A production publisher signature for the exact qualified artifact
is also required before release. CYB-173 remains the already-approved
independent security architecture review required before production.

## Contract and compatibility evidence

- The closed request accepts one bounded Sigma 2.1 basic rule, one exact
  one-to-one mapping, one lower-or-equal policy, one target binding, and one
  expected helper identity.
- Elastic ES|QL, Splunk SPL, and Sentinel KQL are candidate backends at exact
  package versions and commits. Security Onion remains unavailable because the
  audited OpenSearch backend does not emit COH's typed OQL contract.
- A successful helper response is always `compiled_untrusted`. Schema rebinding
  and exactly one named target-native validator are mandatory before a
  query-free `native_validated` receipt may return.
- Unsupported, denied, partially converted, schema-drifted, stderr-bearing,
  truncated, oversized, malformed, or provenance-substituted results release no
  native query through the handoff.

The authoritative fixtures, schemas, capability snapshot, denial corpus,
compatibility matrix, helper attestation, provenance receipt, and redacted
trace are under `contracts/pysigma-helper/v1` and are bound by
`CYB-105-artifacts.sha256`.

## Adversarial and lifecycle evidence

The source-level helper corpus covers deterministic compilation across all
three candidate backends; concurrent and repeated requests; malformed and
duplicate YAML; anchors and alias bombs; regular expressions, correlation, and
other unsupported features; bounded condition expansion; oversize input;
missing mappings; and redacted diagnostics. The Go corpus additionally covers
signed-manifest and attestation tamper, publisher revocation, backend/mapping/
artifact substitution, stale attestation, malformed and oversized output,
stderr and truncation, timeout, cancellation, crash then clean retry, exact
replay, concurrency, schema drift, validator substitution, and unsupported
handoff.

No audit or diagnostic artifact contains Sigma source, generated query text,
literals, field names, credentials, paths, or stderr. The recorded redacted
trace reports all exposure flags false.

## Reproducible bundle and vulnerability correction

CPython 3.13.15, uv 0.12.7, PyInstaller 6.22.2, pySigma 1.5.0, each backend,
and every selected wheel are exact and hash-pinned. Restore and both clean
builds run offline with dependency resolution disabled. The two builds produce
the same `osx-arm64` digest shown above.

The first complete lock audit found DiskCache 5.6.3 affected by
CVE-2025-69872 / GHSA-w8v5-vhqr-4h9v. The helper never uses pySigma's remote
MITRE modules, so the runtime lock now omits `diskcache` and
`diskcache-stubs`; PyInstaller explicitly excludes those modules and build TOC
analysis fails if they reappear. The resulting 22-wheel selection returned zero
OSV findings. The recorded snapshot is
`CYB-105-pysigma-vulnerability-snapshot.json`.

## Verification results

| Verification | Result |
|---|---|
| Helper source tests | 10 passed |
| Real frozen process / Go exchange | Passed |
| Focused Go single and 10-repeat | Passed |
| Focused Go race, vet, staticcheck | Passed |
| Architecture and file-size gates | Passed |
| Secret worktree scan | Passed |
| Offline hash-only restore and two-build reproducibility | Passed |
| Network-none signed operation and forbidden import analysis | Passed |
| Selected Python runtime vulnerability inventory | 22 packages, 0 findings |
| Python license inventory | Exact; 5 dispositions awaiting CYB-187 |
| Clean repository baseline | 18/18 stages passed, `vcs_modified=false` |

The clean baseline report is retained externally at
`/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.9enfJb/quality-report.json`.
Its file digest is
`sha256:dd78b876c8458fb944327dbd8c7c189a5e0405328087b590ff4d9983d5436d75`
and its self-digest is
`15781017c6ee2ba951e22035034057180a174e9a5ffefd48beaef9e6b3976e43`.
This repository CI license stage covers the Go/shipped-input inventory; it does
not supersede the separate fail-closed Python gate.

## Migration, recovery, and rollback

No database migration is introduced. Contract v1 consumers must store the full
helper identity, mapping revision, schema digest, response digest, and
validation receipt. An upgrade to any runtime, wheel, backend, profile, RID, or
artifact creates a new identity and requires a fresh vulnerability/license
inventory, two-build reproducibility result, qualification, and publisher-signed
manifest. Retained `compiled_untrusted` results do not cross an identity or
schema revision.

After cancellation or a helper crash, COH records no guessed completion. An
independent retry re-verifies current authority and either replays the exact
digest-bound request or starts a new request identity. Changed reuse conflicts.
Rebuild recovery uses only the verified offline wheelhouse and rechecks every
hash before restoring.

Rollback revokes or removes the new manifest admission before removing its
artifact. A prior helper may be restored only if its exact artifact, authority,
qualification, vulnerability snapshot, and license disposition remain current;
otherwise compilation stays unavailable. Existing audit, provenance, and
redacted failure evidence is retained. Security Onion remains unavailable
rather than falling back to Lucene, PPL, or generic OpenSearch.

## Remaining actions

1. Resolve CYB-187 through authorized legal/open-source compliance review.
2. Update the immutable license approval record and change only the reviewed
   allowlist dispositions; run `check_pysigma_supply_chain.sh gate`.
3. Regenerate this packet and its checksum ledger at the final clean commit,
   rerun the helper verifier and clean full CI, then check tasks 7–8 and the five
   CYB-105 acceptance criteria.
4. Before a production release, obtain the separately tracked CYB-173 security
   architecture review and a production publisher signature for the exact
   qualified artifact.
