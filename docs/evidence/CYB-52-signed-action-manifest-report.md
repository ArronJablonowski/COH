# CYB-52 canonical signed action manifest report

| Field | Value |
|---|---|
| Issue | COH-E05-01 / CYB-52 |
| Requirements | FR-012, SEC-006, SEC-009 |
| Verification date | 2026-08-25 |
| Contracts | `coh.action-manifest/v1` / `1.0.0`; `coh.signed-action/v1` / `1.0.0` |
| Canonical profile | `COH-CJ-1` |
| Design-freeze anchor | Product-owner approval at `8c6012d` |
| Implementation checkpoints | `5b5c63b`, `6053416`, `ccd9ca2` |
| Qualified implementation checkpoint | `ccd9ca22425251e692435d2d1b00b92240b3e64c` |
| Review status | Local technical evidence complete |

## Outcome

COH now has a strict approval-grade action identity distinct from its mutable
action lifecycle record. Canonical manifests bind complete organization,
tenant, case, requestor and owner scope; action type, operation and T0–T4 tier;
exact targets, exclusions and argument digest; tool/version/binary and payload
digests; policy digest/revision and ROE; credential class/reference; execution
zone/isolation; validity, nonce and use count; and rollback/safety-watch state.

The reader produces deterministic `COH-CJ-1` bytes and SHA-256 identity. The
envelope uses domain-separated Ed25519 and independently supplied current signer
authority. Any bound-field change invalidates signature and downstream approval
identity. No raw argument, credential, capability, target value, payload, policy,
ROE, secret, or private key is a contract field. The clean 18-stage baseline is
promotable. No unresolved blocking finding remains for this leaf.

## Acceptance audit

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Bind action, arguments, targets/exclusions, tool/payload, actor/case, policy/ROE, validity, and use count | Strict 30-field manifest schema, canonical fixture, semantic validator, and design trace | Pass |
| Canonical serialization, schema validation, examples, versioning, explicit compatibility | Two-schema bundle; canonical and signed fixtures; `COH-CJ-1`; normative compatibility matrix | Pass |
| Invalid input, denial, timeout/cancellation, and recovery without provenance/policy bypass | 24-case frozen corpus; representation/envelope/authority tests; fresh-context recovery; no partial result | Pass |
| Automated success/failure tests and applicable gates | Focused unit/race/vet/architecture verifier plus clean promotable 18-stage baseline | Pass |
| Required evidence | Schema bundle, canonical/signed fixtures, compatibility matrix, focused contract-test log, baseline report, design, checksum ledger | Pass |

## Field ownership and authority proof

The existing `coh.domain/v1` `action` kind remains a lifecycle summary. It can
record planned, policy-checked, approval, execution, confirmation, verified,
compensated, uncertain, denied, or cancelled state, but it cannot serve as the
approval-grade manifest and is never silently upgraded.

The signed manifest owns immutable requested capability facts. Current actor
and key state, policy bundle verification, approval eligibility/consumption,
credential resolution, runner/zone attestation, audit/evidence health, E-stop,
and dispatch remain independent trusted inputs. A valid signature therefore
proves one actor signed one exact manifest; it grants no bearer authority.

Raw arguments and sensitive values stay behind their owning boundaries. Their
canonical digests and opaque classifications bind exact content without copying
it into workflow, approval, audit, API, or evidence records. Syntactically valid
tool, credential-class, target, and zone tokens are preserved exactly, while
later signed policy must default-deny unregistered capabilities.

## Canonicalization and mutation proof

Input is capped at 64 KiB and processed through bounded unique-key `COH-CJ-1`
decoding. Unknown or missing fields, duplicate keys, trailing content, invalid
UTF-8/JSON, float/exponent/negative-zero forms, malformed identifiers, digests,
versions, timestamps, and nonce deny. All 30 fields are required, including
nullable fields, so omission cannot collapse into explicit `null`.

Target/exclusion sets must arrive sorted and unique and must be disjoint. The
reader rejects rather than silently normalizing authority-bearing sets. Validity
must be increasing and no longer than 24 hours. Credential class/reference null
semantics are exact. T2/T3 require rollback; T4 requires ROE, rollback, safety
watch, and one use.

Tests prove alternate member order and whitespace canonicalize to the exact
fixture bytes/digest, and caller input remains unmodified. During development,
the ownership tests caught and corrected an empty-slice clone that changed `[]`
to `null`. Validated and verified results now keep internal ownership and return
defensive copies, preventing downstream mutation of verified bytes or slices.

## Signature and signer-authority proof

The signature covers
`COH-SIGNED-ACTION-V1\0 || canonical_manifest_bytes`. V1 accepts only Ed25519.
The envelope binds manifest digest, signer actor, key ID, positive key revision,
algorithm, and signature. Signer actor must equal requestor, and trusted current
authority must independently match actor, key ID, revision, active state, and
public key.

Tests deny schema/algorithm substitution, changed digest, changed bound field
with recomputed public digest, changed signer/key/revision, inactive authority,
wrong public key, unknown/duplicate envelope fields, malformed signature, and
requestor substitution. The canonical signed fixture uses a deterministic inert
test key; no private key is stored.

## Failure, cancellation, recovery, and compatibility

Failures return closed error codes and stable reasons without echoing caller
content. No canonical or verified result is returned after invalid input,
semantic denial, cancellation, or timeout. A fresh context can rerun immutable
input from the beginning; partial decoder/verifier state is not retained.

The compatibility matrix treats added required fields, renamed/retyped fields,
canonicalization changes, and signature-domain changes as breaking. Unknown
fields, versions, algorithms, and tiers deny. Migration preserves original
signed bytes and creates a separately signed new object with lineage. Any
policy/ROE/credential/tool/payload/target/argument/time/use change is a new
action identity requiring fresh policy and approval.

## Verification evidence

Clean checkpoint `ccd9ca22425251e692435d2d1b00b92240b3e64c` passed the
focused verifier. Its log SHA-256 is
`e7783a97987a14ecb5e784c6f9715715bfe8030589671b407207a5211151c8d2`.

The same checkpoint passed all 18 baseline stages with
`quality_gate_promotable=true`. The report digest is
`228b8f679eb3afc91e99c3ec224fb0da45e80b1188c900660e6eb0ee4e0a3730`;
the report-file SHA-256 is
`721c161bc8fb0720e110edabeb1cf24a0f5e24dd15d2c9a2120af5e66e9a04db`.
Provenance records 476 source files, source digest
`e21321c186d78a3b8cb8d971683e63b8d03fbbb826089d399b520a1c1551599d`,
Go 1.26.7 on darwin/arm64, and clean VCS state.

## Reproduction

```sh
./scripts/verify_action_manifests.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- FR-012 durable transition persistence and uncertain-side-effect handling are
  implemented by later workflow/broker leaves; this manifest freezes identity
  across those states and forbids identity-changing retry.
- OPA evaluation, approval fingerprints/lifecycle, T4 dual approval,
  tamper-evident audit, and broker dispatch composition remain E05-02 through
  E05-06.
- Independent security architecture review remains required before the first
  production release.
