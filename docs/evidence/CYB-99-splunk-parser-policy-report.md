# CYB-99 Splunk parser policy report

| Field | Value |
|---|---|
| Issue | COH-E14-02 / CYB-99 |
| Requirements | FR-046, FR-051 |
| Validator | `splunk-parser-1.0.0` |
| Implementation commits | `e54d3de` through `e1cf2a5` |
| Focused verification | `scripts/verify_splunk_parser_policy.sh` |
| Full CI evidence | Recorded in the CYB-99 closure comment and attached CI report |
| Residual production condition | Independent security architecture review before first production release |

## Delivered boundary

COH accepts only a restricted logical SPL profile. The local tokenizer,
recursive parser, typed schema binder, and canonical compiler are the sole
authorization decision. Exactly six commands are admitted: `search`,
`fields`, `table`, `stats`, `sort`, and `head`. Thirty-six risky, indirect,
alternate-source, saved-state, lookup, and external-effect commands have stable
specific denials; every other command is unclassified and denied.

The compiler selects one admitted logical resource, maps it to an
administrator-configured index, maps only discovered logical fields, injects
configured tenant/source filters, binds the exact UTC half-open time range and
hard bounds, and emits deterministic native SPL without accepting raw native
fragments. Subsearches inherit the same resource, schema, scope, authority, and
limits; depth, count, projection, and row output are independently bounded.

After local acceptance, the adapter posts only the canonical candidate to
`/services/search/v2/parser` with `output_mode=json`, `parse_only=true`,
`enable_lookups=false`, and `reload_macros=false`. The strict bounded response
must report the exact locally emitted command multiset. The authenticated
parser receipt is then folded into the final self-verifying plan digest. A
vendor response can deny or make the operation unavailable; it cannot widen or
authorize a local plan.

## Compatibility and qualification matrix

| Deployment | Parser endpoint | Local policy | Fixture | Outcome |
|---|---|---|---|---|
| Splunk Enterprise 9.4 search head | v2 POST | `splunk-parser-1.0.0` | Sanitized documented shape | Supported after deployment qualification |
| Splunk Enterprise 10.0 search head | v2 POST | `splunk-parser-1.0.0` | Sanitized documented shape | Supported after deployment qualification |
| Splunk Cloud | Not qualified | N/A | None | Unsupported |
| v1/unversioned parser | Disabled/deprecated | N/A | None | Denied |

The deterministic fixtures prove decoder and conformance behavior; they are not
a substitute for live deployment identity, version, capability, TLS, index,
and field qualification. The existing CYB-95 boundary performs that check and
validation retains only schema produced under the exact live capability digest
and expiry.

## Adversarial and audit evidence

The executable denial corpus contains 24 safe inputs. All 36 classified
commands are tested at outer and recursive positions. Additional coverage
includes invalid UTF-8, controls, quotes/escapes, macros/backticks, unknown
syntax, depth/token/byte limits, type confusion, index/field widening,
subsearch mismatch, plan/decision/registry tamper, strict vendor JSON,
semantic drift, Query-ID substitution, deterministic replay, 32-way
concurrency, stale capability/schema, cancellation, timeout/outage recovery,
and policy revocation. The seeded fuzz target completed without a panic or
acceptance bypass.

Public policy-decision, zero-exposure audit, denial-corpus, and revocation
fixtures are strict and digest-bound. Common validation evidence contains only
outcome, reason codes, validator identity, canonical query digest, and
provenance digest. Native SPL, literals, credentials, vendor response bodies,
and future SIDs remain adapter-internal and are absent from public evidence.

## Migration and rollback

- Deploy the discovery and parser validator together; enable validation only
  after a fresh live qualification and complete schema discovery.
- A validator, registry, grammar, field-permission, command, endpoint, or bound
  change requires a reviewed contract revision and new adversarial evidence.
- Invalidate capability, schema, validation, and retained-plan state whenever
  the validator/configuration changes. Never translate or reuse an older plan.
- Rollback disables new Splunk validation, revokes retained decisions, clears
  adapter-held plans, restores the prior reviewed binary/configuration, and
  requires fresh qualification before retry. No uncertain vendor result or
  prior acceptance is replayed across rollback.

## Acceptance assessment

| Acceptance criterion | Evidence | Outcome |
|---|---|---|
| Expansion disabled; risky, saved, macro, lookup, and custom commands recursively denied | Registry, HTTP preflight, denial corpus, recursive policy tests | Pass |
| Default-deny actor/scope binding, redaction, replay/tamper/stale/revocation | Plan contracts, adapter runtime, audit/revocation fixtures | Pass |
| Invalid input, denial, timeout/cancel, and recovery preserve provenance | Parser, transport, and adapter adversarial suites | Pass |
| Success/failure automation and applicable CI/race/architecture/secret/license/size gates | Focused verifier and clean baseline attachment | Pass |
| Adversarial trace, policy decision, audit proof, denial/revocation evidence | Versioned fixtures, report, verifier, checksums | Pass |

No CYB-99 blocking finding remains. The approved product-level follow-up is
unchanged: obtain an independent security architecture review before the first
production release.
