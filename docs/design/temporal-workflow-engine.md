# Temporal WorkflowEngine adapter

| Field | Value |
|---|---|
| Issue | COH-E03-05 / CYB-46 |
| Requirements | FR-011, FR-012, NFR-012, EVAL-015 |
| Contract | `coh.workflow/v1` |
| Registered workflow | `coh.operation.v1` |
| Temporal SDK | Go SDK v1.45.0; API v1.62.12 |
| History classification | Operational identifiers, version tokens, and SHA-256 digests |
| Status | Implemented and verified |

## Boundary decision

`workflow.Engine` is the transport-facing durable orchestration port. Its five
operations are `Start`, `Signal`, `Query`, `Cancel`, and `Replay`. A concrete
driver must be wrapped with `workflow.GuardEngine`, which validates inputs,
validates returned scope and version, maps context cancellation and deadlines,
and removes untyped backend detail.

The port contains no Temporal client, protobuf, history bytes, filesystem path,
activity callback, SQL, credential, policy evaluator, connector, runner, or
generic payload. Runtime requests carry complete organization/tenant/case
scope, UUID workflow identity, registered tokens, bounded idempotency keys, and
SHA-256 digests. Replay accepts only a registered fixture ID; retained history
bytes remain adapter-owned.

## Runtime mapping

| Port operation | Temporal operation | Contract behavior |
|---|---|---|
| `Start` | `ExecuteWorkflow` | Workflow ID equals operation UUID; conflict and reuse policies reject duplicates |
| `Signal` | `SignalWorkflow` | Fixed `coh.signal.v1` channel; only `advance` and `complete` are public kinds |
| `Query` | `QueryWorkflow` | Fixed `coh.snapshot.v1` query; returned case scope and identity must match |
| `Cancel` | reason-digest signal, then `CancelWorkflow` | Cancellation intent is recorded before cooperative cancellation is requested |
| `Replay` | `WorkflowReplayer.ReplayWorkflowHistory` | Registered history is rehashed, parsed, and replayed with the retained v1 definition |

The adapter uses the SDK's real exported client signatures through a narrow
internal client interface. A compile-time assertion proves that
`client.Client` implements it; tests use a bounded fake only to inject duplicate,
context, and failure outcomes without starting a network service.

## Idempotency and denial

Starts use the operation UUID as Temporal's business workflow ID and set both
running-conflict and completed-reuse policies to reject duplicates. When a
duplicate is returned, the adapter queries the durable start digest. An exact
request returns the existing run with `Replayed=true`; different scope or input
returns `conflict`.

Signal histories store SHA-256 hashes of the idempotency key and complete signal
request, never the caller's opaque key. `coh.operation.v1` remembers those
digests deterministically. An exact signal replay is ignored. Reusing the same
idempotency hash for changed input moves the workflow snapshot to `denied`; it
does not advance or complete. Cancellation uses the same hashed signal envelope
before the SDK cancellation request, making a retry safe if cancellation fails
after the reason signal is accepted.

The workflow performs no activities and has no connector or policy reference.
Later consequential-action workflows must persist the FR-012 state machine and
submit typed intents through `ActionAuthority`; this adapter cannot bypass that
route.

## Version and replay strategy

The initial definition is registered by the immutable name
`coh.operation.v1`. An incompatible implementation must receive a new
registered name; v1 remains compiled and replayable while any retained v1
history exists. `OperationWorkflow` updates a bounded snapshot only from
recorded signals and cancellation. It uses no wall clock, random source,
network, filesystem, goroutine, mutable global, or activity side effect.

The retained fixture
`internal/workflow/temporaladapter/testdata/coh-operation-v1-history.json`
contains a real Temporal event-history shape through the first workflow task.
Its input contains only operation/case identifiers, registered kind/version,
and input/start digests. The verifier replays it five times with Temporal's
official replayer. Digest tampering is denied before parsing or replay.

## Dependency decision

The initial review evaluated the then-current SDK v1.48.0. Versions v1.46.0
through v1.48.0 introduced a module-graph dependency on
`github.com/nexus-rpc/nexus-proto-annotations v0.1.0`; the published Go module
contains no license file. The closed license gate therefore rejected those
versions. v1.45.0 is the newest SDK before that graph change and supports all
APIs used here. Its required API v1.62.12 is pinned alongside it.

The vulnerability gate then identified fixed-version findings in transitive
`golang.org/x/net` and `golang.org/x/text`. They are explicitly raised to
v0.56.0 and v0.39.0. The locked vulnerability database reports zero findings.
The complete 91-module graph and exact license-file hashes remain closed inputs.

## Verification

```sh
scripts/verify_temporal_adapter.sh
scripts/run_ci_quality.sh baseline
```

The dedicated verifier runs unit, race, repeated retained-history replay, vet,
and architecture checks. The baseline additionally covers formatting, size,
workflow policy, secrets, static analysis, exact licenses/dependencies,
vulnerabilities, SBOM, supply chain, and provenance.
