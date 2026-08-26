# CYB-61 Codex runtime bridge verification report

| Field | Value |
|---|---|
| Issue | COH-E07-06 / CYB-61 |
| Requirements | FR-036, FR-039 |
| Verification date | 2026-08-26 |
| Verified checkpoint | `1ef84be4557967ff6e10b896d09111a46e5eae2c` |
| Aggregate result | Pass |

## Outcome

COH now treats Codex as a qualified external-agent runtime behind the
provider-neutral contract. The primary bridge is a typed, bounded Codex App
Server v2 JSON-RPC client. It is frozen to Codex CLI `0.145.0`, binary SHA-256
`1da3f4e0e96028b8a771814293c3033dafd1971f943f6c7e79b0897fe705f590`,
and generated App Server v2 schema SHA-256
`821c237d2ed4c9b736c82cdd5f302e881be1d5994abb3959060b795d4dd442ce`.

Dispatch requires the exact capability and provider tuple plus an unexpired
signed qualification. A managed launch attestation binds the runtime,
protocol, requested and actual model, immutable model revision, stdio
transport, fixed workspace, isolated Codex home, read-only sandbox,
`untrusted` approvals, disabled rules/hooks/web/mutation, broker-only MCP
mode, invocation-scoped credential channel, connected route, managed config,
and environment allowlist before the first handshake message is sent.

The App Server path creates one ephemeral thread and turn, permits only the
pinned dynamic-tool experimental surface, and rejects native command,
file-change, MCP/app, web, skill, shell, mutation, user-input, approval,
reroute, and unknown requests. Dynamic tool start, broker request, broker
result, and completion events are correlated by call ID, name, canonical
arguments, and success state. Calls execute only through the COH tool broker;
typed call and result items retain the schema and result digests, including
broker denials.

The bridge enforces exact JSON decoding and request correlation, frame/event/
trace/prompt/output/token/time ceilings, terminal usage and turn state,
cancellation through `turn/interrupt`, disconnected and malformed-stream
handling, and redacted errors. Failures after protocol activity retain a
digest of the bounded raw trace without putting prompts, credentials, tool
values, or vendor error bodies in the error message.

`codex exec` is a separately qualified, explicitly selected batch fallback.
It uses a fixed cwd, ephemeral JSONL, ignored user config, strict config,
read-only sandbox, exact model, optional output schema, empty caller
environment, bounded stdin/stdout/stderr/deadline, and an invocation-scoped
credential channel supplied by the managed runner. There is no automatic App
Server-to-exec fallback. Batch requests containing tools are reported as
unsupported because the JSONL surface cannot prove broker mediation; the
bridge does not weaken the broker-only boundary to add them.

## Acceptance mapping

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| App Server/SDK is the external-agent runtime and exec is only a bounded batch fallback with broker-controlled tools | Typed App Server bridge, exact managed launch tuple, explicit runtime selector, exact exec argv test, no-fallback tests, and explicit rejection of exec tools that cannot prove broker mediation | Pass |
| Only typed allowlisted operations are used; capability/resource bounds, cancellation, credential redaction, and unsupported behavior are explicit | Exact wire types/decoders, launch attestation, signed qualification, bounds checks, interrupt tests, redacted typed errors, native-request denials, and batch-tool unsupported result | Pass |
| Invalid input, denial, timeout/cancellation, and recovery preserve provenance and policy | Unknown-field, reroute, route, sampling, qualification, broker digest/denial, lifecycle, failed-turn, disconnect, timeout, cancellation, trace-overflow, and clean independent-retry tests | Pass |
| Applicable automated gates pass | Dedicated structural/unit/repeat/race/vet/static-analysis/architecture/size/link/diff verifier and all 18 clean baseline stages | Pass |
| Required fixture, capability, conformance, and redacted trace evidence cross-references CYB-61 and FR-036/FR-039 | Two official-shape fixtures, public capability snapshot, six-case neutral conformance suite, this report, redacted trace, and checksum manifest | Pass |

## Frozen surface and exclusions

- Adapter version: `1.0.0`.
- Primary runtime: `codex-app-server`, App Server v2 over managed stdio.
- Secondary runtime: explicitly selected `codex-exec` JSONL batch mode.
- Model: requested and actual model must both be `gpt-5.6-terra` for this
  snapshot; model rerouting is denied.
- State: one ephemeral, stateless thread; session resumption is absent.
- Sampling: temperature milli `0`, top-p millionths `1000000`, seed `0`,
  medium reasoning effort, and concise summary.
- Sandbox: restricted read-only workspace `/workspace`; mutation is disabled.
- Tools: App Server `dynamicTools` only, with complete broker lifecycle
  correlation. Native runtime tools and generic passthrough are denied.
- Batch exclusions: tools, resume, images, added directories, profiles, local
  providers, dangerous flags, ambient environment, and automatic failover.
- Any unknown operation, event, field, status, output kind, identity drift,
  oversized document, missing usage/terminal, or incomplete tool lifecycle
  fails closed.

## Capability and qualification

`contracts/provider/codex-runtime/v1/capability.json` has provider-contract
digest:

```text
sha256:abca41faee87118e28fb4135accbdfa624c31350d723168f75df3c4036295ee5
```

Its file SHA-256 is
`ccb1be8488134b8b60470e1b687473fcc34f4e349befb41ed5c7c46b1e2ecc61`.
Discovery and published canonical bytes match exactly. Runtime dispatch
resolves a signed, unexpired CYB-56 qualification for the exact capability
and provider tuple before launch. Qualification expiry, tuple drift, route
drift, model mismatch, runtime/schema mismatch, or launch-policy drift denies
dispatch without sending an App Server document.

The provider-neutral conformance evaluator passes all six mandatory cases:
capability, structured output, tool call, cancellation, identity/provenance,
and policy route.

## Recorded and adversarial fixtures

The App Server JSONL fixture records initialization, ephemeral thread start,
turn start, agent delta and completion, dynamic broker tool call, tool
completion, reasoning, terminal usage, and completed turn. Its SHA-256 is
`ed35e155fc3ec4128958a58c43771407ce7328ab378be84b890aa1d072c75ece`.

The exec JSONL fixture records thread start, turn start, one agent item, and
terminal usage. Its SHA-256 is
`bd95c2bbca9c861de77b7db5deacf79e6c13fa1f304716eb819476c647473fe0`.

Adversarial tests deny unknown fields/events, unsolicited responses, model
reroutes, native approval/command requests, mismatched Codex home, unsupported
sampling, excessive usage, trace/event/frame/output overflow, malformed and
missing exec terminal events, native exec items, altered tool arguments,
unstarted/unfinished/duplicate tool lifecycles, result-digest mismatch,
expired qualification, failed turns, lost connections, timeouts, and
cancellation. Machine-readable redacted examples are in
`docs/evidence/CYB-61-redacted-error-trace.json`.

## Focused verification

The exact clean checkpoint passed `scripts/verify_codex_runtime_bridge.sh`.
Retained log:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/codex-runtime.w3rJmT/codex-runtime.log
SHA-256 be19a4228ba1db5c9b7c06e41e8afb748162a411c709ca199482dc2a3d08b59a
```

It includes structural capability and fixture checks, unit tests, three
repeated runs, race detection, vet, full static analysis, 60-package
architecture verification with zero violations, file-size enforcement,
Markdown-link checks, and diff validation. Provenance records the exact clean
revision, `modified:false`, Go 1.26.7, and darwin/arm64.

## Clean baseline

The exact checkpoint passed all 18 baseline stages with
`quality_gate_promotable=true`, `verification.outcome=passed`, and
`vcs_modified=false`. Evidence:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.dHgpxt/quality-report.json
```

Embedded report digest:
`c970e21051b40c6a0fd987c5d639851364163ca65cd7d525e1048204bc225ea7`.
Report-file SHA-256:
`07f52543cc8ee50c3927cc4ffbbd129624e2e2881216fe4f16aa294d2041ccdb`.
Provenance records 911 source files, source digest
`264127fefcce132bc94e32f7474c0652faeb0eccd0bca211dc2634ecfdebafdf`,
Go 1.26.7 on darwin/arm64, and revision `1ef84be`.

## Reproduction

```sh
./scripts/verify_codex_runtime_bridge.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- This qualifies only the recorded Codex binary, generated protocol, model,
  route, configuration, environment, parser, state, policy, and bounds tuple;
  it is not a compatibility claim for future Codex fields or versions.
- Production must supply managed App Server and batch launchers, an
  invocation-scoped credential channel, schema and reasoning stores, and the
  COH tool broker. No permissive production launcher is included.
- Material changes to any qualified identity, route, model, protocol,
  configuration, parser, policy, state mode, or limit require a new snapshot,
  fixtures, adversarial tests, and signed qualification.
- Independent security architecture review remains a hard gate before the
  first production release under CYB-173.
