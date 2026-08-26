# CYB-63 native Ollama adapter verification report

| Field | Value |
|---|---|
| Issue | COH-E07-02 / CYB-63 |
| Requirements | FR-033, FR-037, FR-038 |
| Verification date | 2026-08-26 |
| Verified checkpoint | `9e5ba41be7faad06ee0b74558b11db0d69b8c0e4` |
| Aggregate result | Pass |

## Outcome

COH now has a bounded native Ollama adapter behind the provider-neutral
contract. It permits only the exact loopback origin
`http://127.0.0.1:11434` and four native operations: `GET /api/version`,
`GET /api/tags`, `POST /api/show`, and `POST /api/chat`. Vendor objects never
cross the adapter boundary.

Before every chat dispatch, the adapter resolves a current signed
qualification and re-observes the runtime version, exact model name and digest,
template, capabilities, model metadata/tokenizer digest, and context limit.
Those values must match the qualified tuple exactly. A required deployment
attestor must also verify that the observed Ollama process is cloud-disabled
for the runtime/model tuple. Loopback reachability and a matching tag alone do
not establish local data residency.

The transport disables ambient proxies, redirects, compression, HTTP/2
upgrade, credentials, and alternate dial targets. Requests use native messages,
strict function schemas, native JSON-schema `format`, explicit bounded
generation options, `keep_alive:0`, and an explicit stream flag. Function calls
remain broker intents; the adapter has no tool executor.

Non-streaming responses preserve assistant content, local digest-addressed
thinking references, deterministic function-call IDs and arguments, structured
JSON, done reason, detailed usage, timing, requested/actual model identity, and
complete inference provenance. NDJSON streaming accumulates partial content,
thinking, and indexed tool calls, emits correlated COH events, and requires one
`done:true` terminal record with bounded usage. Timeout, outage, or missing
terminal data produces a typed terminal error; malformed, unknown, drifted, or
disordered data fails closed.

## Acceptance mapping

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Native `/api/chat` semantics, model digest/context, tools, streaming, and unsupported behavior | Exact wire types, version/tags/show preflight, request/response translators, NDJSON reducer, recorded fixtures, and drift tests | Pass |
| Typed allowlisted operations, bounds, cancellation, redaction, and partial handling | Four-operation transport, cloud-disabled route attestation, schema/token/context/tool/stream ceilings, typed errors, and denial tests | Pass |
| Invalid input, denial, timeout/cancellation, and recovery retain policy/provenance | Qualification before probes, identity and route binding, cancellation/outage/recovery tests, terminal events, and response provenance | Pass |
| Applicable automated gates pass | Dedicated unit/repeat/race/vet/static-analysis/architecture/size/link/diff verifier and all 18 clean baseline stages | Pass |
| Required verification evidence cross-references CYB-63 and FR-033/037/038 | This report, public capability, six recorded fixtures, redacted trace, checksum manifest, retained logs, and Linear attachment | Pass |

## Frozen native surface and compatibility

- Adapter version: `1.0.0`.
- Vendor surface: `ollama.native.chat/v1`.
- Exact origin: `http://127.0.0.1:11434`.
- Allowed operations: version, tags, show, and chat only.
- Data route: attested cloud-disabled local loopback only.
- State mode: stateless; thinking is retained only in local COH storage behind
  a digest-addressed reference.
- Supported roles: system, user, assistant, and tool.
- Supported items: text, typed JSON, thinking reference, function call, and
  typed function result.
- Supported terminal reasons: `stop` and explicit `length` partial outcome.
- Unsupported: cloud brokerage, credentials, alternate origins, generic
  options, images, log probabilities, undocumented fields, unknown done
  reasons, ambiguous model records, and hidden partial success.

The native Ollama API is not strictly versioned. Any new field, enum member,
runtime, model digest, template, capability set, metadata/tokenizer, parser,
context, sampling, hardware, route, policy, adapter, or limit is a new support
claim requiring fixtures, denial tests, and signed qualification.

## Capability and qualification

`contracts/provider/ollama/v1/capability.json` publishes the exact bounded
snapshot exercised by the tests. Its provider-contract digest is:

```text
sha256:6575d3610a3ae4b455513c50e8b803e7814c64937bde75ea6fd3e2fb36aa7968
```

Its file SHA-256 is
`ed779bcc81a12dcb701ca1f64c7a9521a2b3849bc291c1cc6294131fe2cf5572`.
The adapter discovery result and published canonical bytes match exactly.
Runtime dispatch requires an unexpired signed CYB-56 qualification for the
same capability digest and provider tuple before any identity probe or chat.

The provider-neutral conformance evaluator passes all six mandatory cases:
capability discovery, structured output, tool call, cancellation, identity and
provenance, and policy route.

## Recorded and adversarial fixtures

The native-shape fixture set records runtime version, model tag/digest/details,
show/template/capability/model metadata, completed chat, structured chat, and a
five-record NDJSON stream. Tests mutate these records to deny unknown fields,
model/runtime/template/context drift, partial non-stream responses, unknown done
reasons, excessive usage, unauthorized tools, malformed stream data, time
disorder, duplicate/missing tool indices, and missing terminal data.

HTTP 400/413/422, 401/403, 404, 408/504, 409, 429, 5xx, and unexpected
non-success statuses map to typed COH errors without retaining vendor bodies.
The local profile sends no credential at all. Route-attestation errors are
reduced to a stable denial reason without exposing the attestor detail. The
machine-readable examples are in
`docs/evidence/CYB-63-redacted-error-trace.json`.

## Focused verification

The exact clean checkpoint passed `scripts/verify_ollama_adapter.sh`. The
retained log is:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/ollama.QNAE9g/ollama.log
SHA-256 d5ff8ceb71e98e035006a64c3ba9f3cedbffee17bb939aa03a9f84d0e2e0ace7
```

It includes unit tests, three repeated runs, race detection, vet, full static
analysis, structural fixture/capability checks, unsupported-surface scanning,
57-package architecture verification with zero violations, file-size
enforcement, Markdown-link checks, and diff validation. Provenance records
`9e5ba41`, `modified:false`, Go 1.26.7, and darwin/arm64.

## Clean baseline

The exact clean checkpoint passed all 18 baseline stages with
`quality_gate_promotable=true`, `verification.outcome=passed`, and
`vcs_modified=false`. Evidence is retained at:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.4SwGcH/quality-report.json
```

The embedded report digest is
`af30369f17399bba40d446831aa77b6aec6540868a16e83025c1985e91d2b6e0`;
the report-file SHA-256 is
`41e8b7b90e820339ba74ca20b17635a8989aa4dd37fe2b32c530be06b393b4f7`.
Provenance records 816 source files, source digest
`dc7ddc1b15b8ec9fe91dd3f93fec3063a1837f57cc7f65a03af4513211f3ba40`,
Go 1.26.7 on darwin/arm64, and the exact clean revision.

## Reproduction

```sh
./scripts/verify_ollama_adapter.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- This qualifies only the exact recorded local adapter/runtime/model tuple; it
  is not a blanket claim for arbitrary Ollama hosts, tags, aliases, cloud
  models, runtime versions, or future native API fields.
- The production route verifier must be backed by managed deployment evidence
  that Ollama cloud features are disabled; a permissive verifier is not a
  production implementation.
- Hardware identity is recorded and signed in the capability tuple; later
  platform release-matrix work must obtain the hardware-profile attestation
  from the managed runtime boundary.
- Independent security architecture review remains a hard gate before the
  first production release under CYB-173.
