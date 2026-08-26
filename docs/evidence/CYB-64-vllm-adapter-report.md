# CYB-64 vLLM adapter verification report

| Field | Value |
|---|---|
| Issue | COH-E07-04 / CYB-64 |
| Requirements | FR-035, FR-037, FR-038 |
| Verification date | 2026-08-26 |
| Verified checkpoint | `02e6a285c1aa42c9516764fc50d1a0669d16a806` |
| Aggregate result | Pass |

## Outcome

COH now has a bounded vLLM adapter behind the provider-neutral contract. The
wire surface is frozen to upstream vLLM commit
`796822d141382ab8ce82ef6101c6d802046f94e0`. It permits only the exact origin
`http://127.0.0.1:8000` and five operations: `GET /health`, `GET /version`,
`GET /v1/models`, opt-in read-only `GET /tokenizer_info`, and inference-only
`POST /v1/chat/completions`.

Before every inference dispatch, the adapter resolves an unexpired signed
qualification and re-observes an empty health response, runtime version, the
single served model alias/root/context, the complete tokenizer configuration,
and the chat template. A required managed verifier independently attests the
vLLM package/image, model weights, CUDA/PyTorch/GPU topology, exact tool and
reasoning parsers, launch flags, disabled dev and mutation surfaces, and
stateless mode. Provider-controlled HTTP fields are not trusted to prove those
facts.

The transport rejects proxies, redirects, compression negotiation, HTTP/2
upgrade, credentials, TLS/userinfo, alternate hosts and alternate ports.
Requests contain only typed messages, broker-owned strict function schemas,
strict JSON-schema output, and bounded `max_completion_tokens`, temperature,
top-p and seed values. No generic header/body, template, parser, media,
priority, adapter or vendor-extension passthrough exists.

Non-stream responses preserve text, locally stored digest-addressed reasoning,
deterministic broker tool-call IDs, strict arguments, finish outcome, detailed
usage and raw-response provenance. Streaming accepts only bounded SSE `data:`
records with stable ID/model/time correlation, fragmented tool calls, a finish
chunk, terminal usage and fingerprint, and exactly one `[DONE]`. Populated
provider-only prompt, logprob, routed-expert, transfer, remote-media or metrics
fields fail closed.

## Acceptance mapping

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Pin template, tool/reasoning parsers, served model, state limits and GPU/runtime provenance | Version/model/tokenizer probes, canonical template/tokenizer digests, public capability and required managed attestation tuple | Pass |
| Typed operations, resource bounds, cancellation, credential redaction and explicit partial/unsupported behavior | Five-operation exact-loopback transport, signed qualification, token/tool/message/stream ceilings, typed errors and denial tests | Pass |
| Invalid input, denial, timeout/cancellation and recovery preserve policy/provenance | Exact decoders, identity/route drift tests, cancellation/timeout/outage/recovery tests, redacted terminal events and canonical response digest | Pass |
| Applicable automated gates pass | Dedicated unit/repeat/race/vet/static-analysis/architecture/size/link/diff verifier and all 18 clean baseline stages | Pass |
| Recorded fixture, capability, conformance and redacted trace cross-reference CYB-64 and FR-035/037/038 | Public snapshot, eight fixture artifacts, six-case neutral conformance suite, this report, trace and checksum manifest | Pass |

## Frozen surface and exclusions

- Adapter version: `1.0.0`.
- Vendor surface: `vllm.openai.chat-completions/796822d`.
- Exact origin: `http://127.0.0.1:8000`.
- State mode: stateless. Reasoning references are local COH records, not
  provider-managed conversation state.
- Supported finish reasons: `stop`, `tool_calls`, and explicit `length` as an
  uncertain partial outcome.
- Explicitly denied: `/invocations`, `/server_info`, dev mode, dynamic LoRA or
  prompt adapters, parser plugins, weight/cache/profile/RPC mutation, remote
  media, credentials, alternate origins, ambiguous aliases, populated hidden
  tracing fields, unqualified state and model/template/parser/GPU drift.

The pinned vLLM documentation notes that API-key middleware protects only its
named API prefixes while `/invocations` can expose inference separately. COH
therefore does not use ambient vLLM credentials: the route allowlist makes the
endpoint unreachable through the adapter, and the managed verifier must attest
that the deployment has disabled the route and dev/mutation modes.

Any new route, field, enum, upstream revision, runtime/image/model digest,
tokenizer configuration, template, parser, GPU topology, launch state, policy,
adapter version or bound requires a new snapshot, fixtures, denial tests and
signed qualification.

## Capability and conformance

`contracts/provider/vllm/v1/capability.json` has provider-contract digest:

```text
sha256:58032ab6924a17192ebdd634bf177da59bbf5baad8eacd1bad150958b37476f5
```

Its file SHA-256 is
`ffdc1d118814b3ebabd1e3e066b0640086450a1a6674d6f5c1121358296073cc`.
Discovery and published canonical bytes match exactly. Runtime dispatch
requires an unexpired signed CYB-56 qualification for the same capability and
provider tuple before the first HTTP probe.

The provider-neutral conformance evaluator passes all six mandatory cases:
capability, structured output, tool call, cancellation, identity/provenance and
policy route.

## Recorded and adversarial fixtures

The official-shape fixtures record empty health, version, one ModelCard with
permission data, complete tokenizer init configuration, tool/reasoning and
structured responses, and an eight-record SSE stream with terminal usage and
`[DONE]`. Tests deny unknown fields, model/version/tokenizer/template/context
and fingerprint drift, parent/adapter ambiguity, altered tokenizer kwargs,
populated provider-only metadata, excessive/inconsistent usage, unauthorized
tools, malformed framing, correlation drift, missing terminal data and every
unapproved route.

HTTP 400/413/422, 401/403, 404, 408/504, 409, 429, 5xx and unexpected statuses
map to typed errors without retaining provider bodies. Attestor details,
credentials, prompts and tool values are absent from errors. Machine-readable
examples are in `docs/evidence/CYB-64-redacted-error-trace.json`.

## Focused verification

The clean checkpoint passed `scripts/verify_vllm_adapter.sh`. Retained log:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/vllm.lvo2oq/vllm.log
SHA-256 1ada8157b2b7c7afc78bde7ba72708bd973fed20b9cef317f310b178a2c68aa6
```

It includes structural capability/fixture checks, unit tests, three repeated
runs, race detection, vet, full static analysis, 59-package architecture
verification with zero violations, file-size enforcement, link checks and diff
validation.

## Clean baseline

The exact checkpoint passed all 18 baseline stages with
`quality_gate_promotable=true`, `verification.outcome=passed`, and
`vcs_modified=false`. Evidence:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.vSTygB/quality-report.json
```

Embedded report digest:
`4a59111a58644339611986502d48eb853389af2e579adcec1d8c56069a8bbf0f`.
Report-file SHA-256:
`d3f09183c544a90cb1ead646c874818c94b1fdec9ff5eb30db07690a649db14b`.
Provenance records 885 source files, source digest
`343b06705d9c69fdedf692d662c216b552d772734fbd21db641d515e36e2e0d9`,
Go 1.26.7 on darwin/arm64 and revision `02e6a28`.

## Reproduction

```sh
./scripts/verify_vllm_adapter.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- This qualifies only the recorded adapter/runtime/model/parser/GPU tuple, not
  arbitrary vLLM deployments or future compatible-looking fields.
- Production must supply a managed verifier backed by deployment evidence; no
  permissive production verifier is included.
- Independent security architecture review remains a hard gate before the
  first production release under CYB-173.
