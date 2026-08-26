# Provider contract and qualification suite v1

| Field | Value |
|---|---|
| Contract version | `1.0.0` |
| Canonicalization | `COH-CJ-1` |
| Digest | Domain-separated SHA-256 |
| Requirements | FR-031, FR-037, FR-038, EVAL-028 |

This contract is the provider-neutral boundary between COH workflows and model
provider adapters. It preserves typed messages and content items, typed tool
definitions/calls/results, structured-output constraints, streaming order,
usage, cancellation, terminal state, capability discovery, provider identity,
inference provenance, and qualification evidence. It does not expose a generic
vendor request, options map, headers map, or passthrough JSON field.

## Contract bundle

| Schema | Purpose |
|---|---|
| `capability.schema.json` | Exact provider identity and supported behavior/limits |
| `inference-request.schema.json` | Typed input, tools, output constraint, state, sampling, and route |
| `inference-response.schema.json` | Typed output, terminal state, usage, and actual provenance |
| `stream-event.schema.json` | Ordered deltas and exactly one terminal response or error |
| `qualification-record.schema.json` | Time-bounded release-matrix conformance evidence |
| `signed-qualification.schema.json` | Ed25519 envelope and current qualifier authority binding |

All schemas use JSON Schema draft 2020-12, reject unknown members, and pin
`schema_version` plus `contract_version`. Implementations must reject duplicate
JSON names, trailing values, invalid UTF-8, non-integer numbers where an
integer is required, and input above the documented decoder bound before
canonicalization.

## Canonicalization and digests

Objects use the repository-wide `COH-CJ-1` profile defined by
`contracts/domain/v1/README.md`. A digest is lowercase
`sha256:<64 lowercase hexadecimal characters>`. The following domains prevent
cross-type substitution:

```text
COH-PROVIDER-CAPABILITY-V1\0
COH-PROVIDER-REQUEST-V1\0
COH-PROVIDER-RESPONSE-V1\0
COH-PROVIDER-STREAM-EVENT-V1\0
COH-PROVIDER-QUALIFICATION-V1\0
COH-SIGNED-PROVIDER-QUALIFICATION-V1\0
```

Set-like arrays identified by a schema must already be sorted and unique.
Sequence-bearing arrays retain their declared order. A logical object that
validates but is encoded with different member order or whitespace produces
the same canonical bytes and digest.

## Exact provider tuple

A provider endpoint is qualified only as the exact tuple of:

- provider kind and adapter version;
- endpoint identity digest and approved data route;
- requested/served model names and immutable model revision or weights digest;
- runtime name/version/digest and tokenizer name/version/digest;
- chat template and tool/reasoning parser names plus digests;
- context limit, supported state mode, sampling profile, and hardware profile;
- policy revision and provider capability digest; and
- platform/release-matrix entry used by the qualification run.

An inference records both requested and actual values. Alias resolution,
fallback, model replacement, template/parser changes, runtime changes,
tokenizer changes, hardware changes, route changes, policy changes, capability
changes, or expired evidence invalidate qualification unless the new tuple has
its own passing record.

## Capabilities and admission

Capability discovery returns a typed immutable snapshot. It declares supported
message roles and content kinds, tool calls, structured output, streaming,
cancellation, state modes, usage accounting, and hard limits. A request is
admitted only when every requested behavior is present in both the current
capability snapshot and an unexpired passing qualification record for the
exact tuple. Unknown, partially qualified, stale, or materially changed
capability fails closed as unsupported.

Qualification contains six mandatory conformance cases: capability discovery,
structured output, tool call, cancellation, identity/provenance, and policy
route. Each case binds a fixture digest, outcome, trace digest, and duration.
Every case must pass. Qualification cannot be inferred from endpoint health,
successful decoding, adapter presence, or a compatible model name.

The qualification payload is accepted only inside an Ed25519 envelope. The
trusted control plane supplies the qualifier identity, key ID/revision,
approval revision, current active/approved state, and public key. Request data
cannot select or widen that authority. The signature covers the exact
COH-CJ-1 payload bytes plus qualifier identity, key ID/revision, and approval
revision under the signed-qualification domain. A digest or signature
mismatch, unknown/stale key, inactive qualifier, or changed replay is denied.

## Streaming, cancellation, and recovery

Stream events bind the request and attempt and start at sequence zero. Sequence
numbers are contiguous. Deltas are typed content or usage updates. Exactly one
terminal response or terminal error ends the stream, and no event is valid
after it. Cancellation must reach the adapter transport; a terminal canceled
result is distinct from timeout, denial, provider failure, and uncertain
completion. Retry or recovery uses a new attempt ID while retaining the
original request ID and provenance chain.

## State and data handling

State mode is explicit: `stateless`, `client_managed`, or `provider_managed`.
Opaque state references are identifiers, never credentials or hidden vendor
payloads. The data route is explicit: `local`, `approved_external`, or
`air_gapped`. Provider-managed storage is disabled unless the state mode and
route are both policy-approved and qualified. Prompts, tool arguments,
responses, reasoning data, credentials, and state values must not appear in
capability or qualification records.

## Error taxonomy

Terminal errors use one of `invalid_input`, `denied`, `unsupported`,
`canceled`, `timeout`, `unavailable`, `conflict`, or `internal`. They contain a
stable bounded reason code and redacted message. Credentials, request content,
tool arguments, raw provider bodies, and opaque state values are forbidden.

See `compatibility-matrix.md` for migration and mixed-version behavior.
