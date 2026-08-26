# CYB-56 provider contract and qualification verification report

| Field | Value |
|---|---|
| Issue | COH-E07-01 / CYB-56 |
| Requirements | FR-031, FR-037, FR-038, EVAL-028 |
| Verification date | 2026-08-26 |
| Verified checkpoint | `e48e20bc62a8cc62cd6cb7dbfd77c842119ceb5a` |
| Aggregate result | Pass |

## Outcome

COH now has a provider-neutral v1 inference boundary covering typed messages
and content items, typed tool definitions/calls/results, strict structured
outputs, streaming, usage, cancellation and timeout, explicit state, capability
discovery, requested/actual provider identity, complete inference provenance,
and release-matrix qualification records. No generic vendor request, options,
headers, passthrough object, credential, secret, or API-key field crosses the
contract.

A provider tuple cannot serve a workflow merely because an endpoint is
reachable or a model name matches. Admission requires an unexpired capability
snapshot and a passing six-case qualification record for the exact provider,
adapter, endpoint, route, model revision/weights, runtime, tokenizer, chat
template, tool/reasoning parsers, context, sampling, hardware, state mode,
policy revision, platform, deployment, and network profile.

Qualification records are carried in an Ed25519 envelope. The signature binds
the canonical record plus qualifier identity, key ID/revision, and approval
revision. The trusted control plane supplies current active and approved
qualifier authority. Digest/signature tamper, stale authority, expiry,
capability or identity drift, incomplete conformance, exact replay, and changed
ID collision are handled explicitly and fail closed.

## Acceptance mapping

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Contract covers typed messages, tools, structured outputs, usage, state, cancellation, streaming, capability discovery, identity, and qualification | Six strict public schemas, Go contract types/validators, stream state machine, signed qualification registry, and provider-neutral conformance evaluator | Pass |
| Canonical serialization, schema validation, positive/negative examples, versioning, and explicit compatibility | COH-CJ-1 domain-separated decoders; exact-shape/schema verifier; canonical capability/qualification fixtures; eight-case denial corpus; compatibility matrix | Pass |
| Invalid input, denial, timeout/cancellation, and recovery preserve provenance and policy | Duplicate/unknown/trailing/non-integer denial; exact authority/provenance bindings; canceled/timeout traces; retry recovery; stream terminal/sequence enforcement | Pass |
| Automated success/failure paths pass applicable gates | Dedicated unit/repeat/race/vet/schema/architecture/size/link/diff verifier and all 18 clean baseline stages | Pass |
| Evidence cross-references COH-E07-01 and FR-031/037/038/EVAL-028 | This report, public bundle, retained logs, clean baseline, checksum manifest, and Linear attachment | Pass |

## Public schema bundle

`contracts/provider/v1` publishes:

- `capability.schema.json` for immutable discovery snapshots and hard limits;
- `inference-request.schema.json` for typed inputs, tools, structured-output
  constraints, sampling, state, route, and authority bindings;
- `inference-response.schema.json` for typed outputs, usage, terminal outcome,
  actual provider identity, state, and provenance;
- `stream-event.schema.json` for correlated contiguous events and one terminal
  response or error;
- `qualification-record.schema.json` for the six mandatory conformance cases
  and exact release matrix; and
- `signed-qualification.schema.json` for current Ed25519 qualifier authority.

Every schema uses draft 2020-12, pins schema and contract versions, and denies
unknown object members. The Go decoder adds bounded input, unique-key,
single-value, integer-only, exact-shape, semantic, canonicalization, and
immutable-copy enforcement. Schema fields and Go semantics are checked by the
dedicated verifier and contract tests.

## Canonical fixtures and compatibility

The tracked capability and qualification fixtures recover to stable COH-CJ-1
bytes. The capability's domain-separated canonical digest is:

```text
sha256:0d58b09b1f641d043cf02e8c0b1cd130ab6886ca2d3695475cc9e07b3932f6bb
```

The fixture is decoded again from canonical output and retains the same bytes
and digest. Tests also prove returned canonical bytes and typed values do not
expose mutable internal state.

The compatibility matrix treats new providers/models/routes/platforms as new
support claims; material tuple changes invalidate old evidence. Unknown
fields, new semantic kinds, canonicalization changes, weakened bounds, and
mixed readers require a new contract and explicit qualification. Runtime
policy may narrow qualification but can never widen it.

## Denial and recovery coverage

The public denial corpus maps eight mandatory adversarial boundaries to named
tests: unknown field, malformed content, unsupported capability, provider
identity drift, expired qualification, exact replay, changed-ID collision, and
stream sequence tamper. Additional automated cases cover duplicate names,
non-integer numbers, missing required booleans, unsorted sets, digest and
signature tamper, stale/inactive qualifier authority, role/content mismatch,
state/provider mismatch, post-terminal events, canceled contexts, timeout
terminal state, incomplete traces, policy binding, and same-input recovery.

## Provider-neutral qualification suite

`EvaluateConformanceSuite` consumes only validated canonical COH documents and
requires the six sorted cases mandated by EVAL-028:

1. capability discovery;
2. structured output;
3. tool call;
4. cancellation, including the timeout terminal variant;
5. identity and provenance; and
6. policy route.

Every non-capability trace binds the exact capability digest and provider
tuple, request/attempt IDs, state mode, limits, qualification ID, contiguous
stream order, terminal outcome, and response provenance. Structured-output and
tool-call cases must return output matching the exact requested schema/tool
digest. The suite rejects incomplete traces, sequence/correlation tamper,
unqualified behavior, route drift, and missing provenance.

## Focused verification

The exact clean checkpoint passed `scripts/verify_provider_contract.sh`. The
retained log is:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/provider-contract.QZsl7C/provider-contract.log
SHA-256 f9e5068003764dbe77b9f6df4535f5870fe2af5848d383aa7f114508b24ef432
```

It includes unit, three repeated runs, race, vet, six-schema structural and
secret-surface checks, fixture/denial checks, 55-package architecture
verification with zero violations, file-size enforcement, Markdown-link
checks, and diff validation. Provenance records `e48e20b`, `modified:false`, Go
1.26.7, and darwin/arm64.

## Clean baseline

The exact clean checkpoint passed all 18 baseline stages with
`quality_gate_promotable=true`, `verification.outcome=passed`, and
`vcs_modified=false`. Evidence is retained at:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.nQW6zD/quality-report.json
```

The embedded report digest is
`b08cf2315c86678e1e97efe57a7c77013cc7153a1b8709f4ed8f76ac2e318230`;
the report-file SHA-256 is
`98859ccc84911c00e00805eb2020a0277aca74db8d7c455632b0789d9502d509`.
Provenance records 752 source files, source digest
`6a56f342e2f046effcd685a3a23a6eee6744e6d11e4e51f4b29e550a76593a85`,
Go 1.26.7 on darwin/arm64, and the exact clean revision.

## Reproduction

```sh
./scripts/verify_provider_contract.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- This leaf defines and tests the provider-neutral contract and qualification
  evaluator. It does not claim that any vendor adapter is qualified; CYB-63,
  CYB-59, CYB-64, CYB-62, and CYB-61 must supply exact recorded provider
  fixtures and passing release-matrix evidence.
- QualificationRegistry is the in-process reference implementation. A
  multi-replica control plane must provide a durable linearizable registry
  preserving exact replay/collision behavior before claiming that profile.
- Independent security architecture review remains a hard gate before the
  first production release under CYB-173.
