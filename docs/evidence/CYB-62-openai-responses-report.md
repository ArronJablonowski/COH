# CYB-62 OpenAI Responses adapter verification report

| Field | Value |
|---|---|
| Issue | COH-E07-04 / CYB-62 |
| Requirements | FR-032, FR-038, FR-039 |
| Verification date | 2026-08-26 |
| Verified checkpoint | `7869196399bad594205d8d1a8140d3b3859f0935` |
| Aggregate result | Pass |

## Outcome

COH now has a bounded OpenAI Responses adapter behind the provider-neutral
contract. It translates validated canonical requests to the exact approved
`POST https://api.openai.com/v1/responses` operation and returns only validated
COH responses or correlated stream events. OpenAI wire objects, credentials,
headers, and vendor error bodies do not cross the adapter boundary.

Dispatch is fail closed. It requires the exact endpoint and approved external
route, an unexpired signed qualification for the exact capability tuple,
strict digest-resolved schemas, a private credential resolver, TLS 1.2 or
newer with the `api.openai.com` identity, disabled redirects and ambient proxy,
bounded bodies, a pinned token counter, context cancellation, and qualified
input/output/tool/stream limits.

The adapter creates stateless requests with `store:false`, `background:false`,
and `truncation:"disabled"`. Function tools are the only allowed tool class.
It preserves ordered message, reasoning, and function-call items; call IDs;
strict structured JSON; refusals; incomplete outcomes; usage; requested and
actual identity; and encrypted reasoning by opaque digest reference.

Streaming consumes ordered SSE events, enforces vendor sequence and response
correlation, reconstructs text, reasoning summaries, and function arguments,
and emits exactly one validated COH terminal response or error. Transport
outage, deadline expiry, cancellation, and a stream ending without a vendor
terminal event produce typed terminal errors rather than an ambiguous partial
success.

## Acceptance mapping

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Exact supported Responses API surface and compatibility boundary are frozen | Adapter README, exact wire types, request-shape tests, unsupported-surface scan, and recorded fixtures | Pass |
| Secure translation preserves canonical identity, content, tools, structured output, reasoning, usage, and terminal status | Invoke, structured, incomplete, reasoning replay, identity-drift, usage, and strict-schema tests | Pass |
| Streaming preserves order/correlation and terminates on success, refusal, cancellation, timeout, outage, or malformed/partial input | Recorded SSE fixture, reducer tests, sequence/correlation tamper tests, terminal-error tests, and provider-neutral conformance suite | Pass |
| Runtime use requires an exact signed and unexpired qualification | Published capability snapshot, capability/discovery equality test, qualification-registry resolution before dispatch, and drift/expiry denial tests | Pass |
| Credentials, transport, bounds, and errors fail closed without sensitive details | Private credential type/resolver, zeroization test, TLS/route/redirect/proxy tests, request/response/context ceilings, status-map tests, and redacted trace | Pass |
| Automated success and failure paths pass applicable gates | Dedicated unit/repeat/race/vet/static-analysis/architecture/size/link/diff verifier and all 18 clean baseline stages | Pass |

## Frozen vendor surface

- Exact operation: `POST https://api.openai.com/v1/responses`.
- Adapter version: `1.0.0`.
- Vendor surface identity: `openai.responses.create/v1`.
- State mode: stateless only.
- Request invariants: storage disabled, background disabled, truncation
  disabled, bounded output, and no previous response or conversation state.
- Supported tools: strict function definitions only; the adapter never
  executes a function.
- Supported output items: message, function call, and reasoning.
- Supported message content: output text and refusal.
- Supported terminal statuses: completed, failed, incomplete, and cancelled.
- Unknown fields, item/content/status kinds, model or route drift, malformed
  JSON, sequence disorder, oversized input/output, and partial reads fail
  closed.

## Capability and qualification

`contracts/provider/openai-responses/v1/capability.json` publishes the exact
bounded snapshot exercised by the tests. Its provider-contract digest is:

```text
sha256:70325fbd315daee428cc4b4aef1e785d11a29594336325621de6861ef5bba28c
```

Its file SHA-256 is
`73bbb87acbe4942d498f561232faa47191aba82754d858a23e84e1fabe077c6b`.
The adapter discovery result and published canonical bytes must match exactly.
Reachability or a matching model string never qualifies the adapter. Runtime
dispatch resolves a signed, unexpired qualification for the full capability
tuple before making an HTTP request.

The provider-neutral conformance evaluator passes all six mandatory cases:
capability discovery, structured output, tool call, cancellation, identity and
provenance, and policy route.

## Recorded and adversarial fixtures

The retained official-shape fixtures cover an ordered completed response,
strict structured JSON, an incomplete response at the output-token limit, and
an 18-event completed SSE exchange. Tests mutate the fixtures to deny unknown
fields, unsupported output and stream types, bad sequence/correlation, early
completion, missing terminal data, background status, route/model drift,
invalid call IDs, invalid usage, and response-ceiling violations.

HTTP 400/413/422, 401/403, 404, 408/504, 409, 429, 5xx, and unexpected
non-success statuses map to typed COH errors without returning the vendor body.
Credential-resolution errors likewise return only a stable reason. The
machine-readable redacted examples are in
`docs/evidence/CYB-62-redacted-error-trace.json`.

## Focused verification

The exact clean checkpoint passed
`scripts/verify_openai_responses_adapter.sh`. The retained log is:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/openai-responses.CjQsMJ/openai-responses.log
SHA-256 e2f1355877d054dcdfbc97cbecf2bb2f3ac97295b0204f4ece864cbfa23b60ae
```

It includes unit tests, three repeated runs, race detection, vet, full
staticcheck, structural capability and fixture checks, unsupported-surface
scanning, 56-package architecture verification with zero violations,
file-size enforcement, Markdown-link checks, and diff validation. Provenance
records `7869196`, `modified:false`, Go 1.26.7, and darwin/arm64.

## Clean baseline

The exact clean checkpoint passed all 18 baseline stages with
`quality_gate_promotable=true`, `verification.outcome=passed`, and
`vcs_modified=false`. Evidence is retained at:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.S6izev/quality-report.json
```

The embedded report digest is
`8488c372a93fdfb387dc9b04b3a76890ebeee7ee43034eff72735f6e70b189a3`;
the report-file SHA-256 is
`563bc30539dfe360dbfb36204376b1b1f4c8e1ed2a04cf379939c0f6ef2b2b8f`.
Provenance records 782 source files, source digest
`22d57036f9d58ee306b1f8f265fd03f7de473cce2e167d47f41b65b6582aa0e9`,
Go 1.26.7 on darwin/arm64, and the exact clean revision.

## Reproduction

```sh
./scripts/verify_openai_responses_adapter.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- This evidence qualifies the exact recorded adapter capability tuple; it is
  not a blanket compatibility claim for arbitrary OpenAI endpoints, model
  aliases, revisions, or future Responses API fields.
- Any material route, endpoint, model, runtime, tokenizer, parser, policy,
  adapter, state-mode, or limit change requires a new capability snapshot and
  signed qualification.
- Live release-matrix qualification must use an approved credential reference
  and controlled network profile; no credential or live response is retained
  in this repository evidence.
- Independent security architecture review remains a hard gate before the
  first production release under CYB-173.
