# CYB-59 native llama.cpp adapter verification report

| Field | Value |
|---|---|
| Issue | COH-E07-03 / CYB-59 |
| Requirements | FR-034, FR-037, FR-038 |
| Verification date | 2026-08-26 |
| Verified checkpoint | `e1656e2119c445c455d48d6c46cc46dc32b62718` |
| Aggregate result | Pass |

## Outcome

COH now has a bounded native llama.cpp server adapter behind the
provider-neutral contract. It permits only the exact loopback origin
`http://127.0.0.1:8080` and four operations: read-only `GET /health`,
`GET /props`, `GET /v1/models`, and inference-only
`POST /v1/chat/completions`. Vendor objects never cross the adapter boundary.

The wire contract is frozen to upstream llama.cpp commit
`5d5cb4c3a4ea8769490d39a275ee49a45184774d`. Before every inference dispatch,
the adapter resolves an unexpired signed qualification and re-observes health,
the build fingerprint, the single model alias and GGUF path, effective context,
GGUF metadata, active chat template, and template/parser capabilities. A
required managed-runtime verifier independently binds the qualified
llama-server binary digest and GGUF digest and denies router, autoload/download,
agent, MCP, vendor tool execution, remote media, mutable-property, and
non-loopback launch modes.

The transport disables ambient proxies, redirects, compression, HTTP/2
upgrade, credentials, TLS/userinfo, and alternate dial targets. Chat requests
use typed messages, broker-owned strict function schemas/results, documented
JSON-schema constraints, and only bounded `max_tokens`, `temperature`, `top_p`,
and `seed` sampling fields. `cache_prompt:false` makes the stateless intent
explicit. Structured-output and tool-call grammars are never combined: the
adapter reports `unsupported` instead of silently changing either constraint.

Non-streaming responses preserve assistant text, locally stored
digest-addressed reasoning references, deterministic broker call IDs, strict
arguments, finish reason, usage, timings, model/build identity, and inference
provenance. Streaming accepts only bounded SSE `data:` records with stable
completion correlation, assembles fragmented function calls, and requires a
finish chunk, a terminal usage/timing chunk, and exactly one `[DONE]` marker.
Timeout, cancellation, outage, or truncation produces a typed terminal error;
unknown, malformed, drifted, excessive, or unauthorized data fails closed.

## Acceptance mapping

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Chat Completions contract with explicit template, grammar/tools, context, revision, and cancellation | Pinned typed wire surface, properties/model preflight, binary/GGUF route attestation, request/response translators, SSE reducer, and recorded fixtures | Pass |
| Typed allowlisted operations, bounds, cancellation, credential redaction, partial/unsupported behavior | Four-operation transport, exact loopback dialer, signed qualification, schema/token/context/tool/stream ceilings, typed errors, and denial tests | Pass |
| Invalid input, denial, timeout/cancellation, and recovery retain policy/provenance | Pre-dispatch authority binding, identity/route drift tests, active cancellation, timeout, outage/recovery tests, redacted terminal events, and response provenance | Pass |
| Applicable automated gates pass | Dedicated unit/repeat/race/vet/static-analysis/architecture/size/link/diff verifier and all 18 clean baseline stages | Pass |
| Required evidence cross-references CYB-59 and FR-034/037/038 | This report, public capability, six recorded fixture documents, redacted trace, checksum manifest, retained logs, and Linear attachment | Pass |

## Frozen server surface and compatibility

- Adapter version: `1.0.0`.
- Vendor surface: `llama.cpp.server.chat-completions/5d5cb4c`.
- Upstream source: [server API](https://github.com/ggml-org/llama.cpp/blob/5d5cb4c3a4ea8769490d39a275ee49a45184774d/tools/server/README.md), [function calling](https://github.com/ggml-org/llama.cpp/blob/5d5cb4c3a4ea8769490d39a275ee49a45184774d/docs/function-calling.md), and [route implementation](https://github.com/ggml-org/llama.cpp/blob/5d5cb4c3a4ea8769490d39a275ee49a45184774d/tools/server/server.cpp).
- Exact origin: `http://127.0.0.1:8080`.
- Data route: managed and attested local loopback only.
- State mode: stateless; reasoning is retained only in local COH storage behind
  a digest-addressed reference.
- Supported roles: system, user, assistant, and tool.
- Supported items: text, typed JSON, reasoning reference, function call, and
  typed function result.
- Supported finish reasons: `stop`, `tool_calls`, and explicit `length`
  uncertain/partial outcome.
- Unsupported: router or model autoload/download, agent/MCP/vendor-side tool
  execution, remote media, credentials, alternate origins, generic options,
  log probabilities, mutable/admin routes, undocumented fields, ambiguous
  models, competing grammar modes, and hidden partial success.

The llama.cpp server API makes no blanket compatibility claim. Any new field,
route, enum member, build, binary or GGUF digest, alias/path, template,
capability set, parser behavior, context setting, launch mode, sampling profile,
hardware, policy, adapter, or bound is a new support claim requiring fixtures,
denial tests, and signed qualification.

## Capability and qualification

`contracts/provider/llama-cpp/v1/capability.json` publishes the exact bounded
snapshot exercised by the tests. Its provider-contract digest is:

```text
sha256:08ddf44ab37a993e1e908f2cc21a4a20c05bb1b1ab3ce75088bbc83293f821b7
```

Its file SHA-256 is
`a8685e251b9157fe762cb4b0cf674001a1b4efbbd92b339aabeb3d20c8254528`.
The adapter discovery result and published canonical bytes match exactly.
Runtime dispatch requires an unexpired signed CYB-56 qualification for the
same capability digest and provider tuple before any provider probe or chat.

The provider-neutral conformance evaluator passes all six mandatory cases:
capability discovery, structured output, tool call, cancellation,
identity/provenance, and policy route.

## Recorded and adversarial fixtures

The official-shape fixture set records health, complete server properties,
single-model metadata, a completed tool/reasoning response, a structured JSON
response, and an eight-record SSE stream with a `[DONE]` marker. Tests mutate
these records to deny unknown fields, model/build/template/context drift,
runtime sleep, malformed build identity, excessive or inconsistent usage,
unauthorized tools, log probabilities, malformed framing, correlation drift,
and missing terminal data.

HTTP 400/413/422, 401/403, 404, 408/504, 409, 429, 5xx, and unexpected
non-success statuses map to typed COH errors without retaining provider bodies.
The local profile sends no credential. Route-attestation errors are reduced to
a stable denial reason without exposing deployment detail. Machine-readable
examples are in `docs/evidence/CYB-59-redacted-error-trace.json`.

## Focused verification

The exact clean checkpoint passed `scripts/verify_llama_cpp_adapter.sh`. The
retained log is:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/llama-cpp.51YUWC/llama-cpp.log
SHA-256 00425f535dce22901805b91ca559795dfa1e52486cd53d57047c029ed80e49c9
```

It includes structural capability/fixture checks, unit tests, three repeated
runs, race detection, vet, full static analysis, 58-package architecture
verification with zero violations, file-size enforcement, Markdown-link
checks, and diff validation.

## Clean baseline

The exact clean checkpoint passed all 18 baseline stages with
`quality_gate_promotable=true`, `verification.outcome=passed`, and
`vcs_modified=false`. Evidence is retained at:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.h76tBy/quality-report.json
```

The embedded report digest is
`a053500c44ae055b5afba6c342973e2415c2cfd9c1a56c4cf835ee560ef8f18d`;
the report-file SHA-256 is
`a2ab8e64d34c5f35fa639f5b5be2f079e2194a407f08ab33cce71b037385f349`.
Provenance records 850 source files, source digest
`5daff612e8b91555bc5f563552ed364b31248ff864a1b264dd775358ee61c4be`,
Go 1.26.7 on darwin/arm64, and the exact clean revision.

## Reproduction

```sh
./scripts/verify_llama_cpp_adapter.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- This qualifies only the exact recorded native adapter/runtime/model tuple;
  it is not a blanket claim for arbitrary llama.cpp servers, router mode,
  builds, models, templates, or future Chat Completions fields.
- The production route verifier must be backed by managed deployment evidence;
  no permissive production verifier is supplied by the adapter package.
- Hardware identity is signed in the capability tuple; platform packaging must
  supply its attestation from the managed runtime boundary.
- Independent security architecture review remains a hard gate before the
  first production release under CYB-173.
