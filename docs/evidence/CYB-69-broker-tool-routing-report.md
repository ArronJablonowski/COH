# CYB-69 broker-only tool routing verification report

| Field | Value |
|---|---|
| Issue | COH-E08-03 / CYB-69 |
| Requirements | FR-018, SEC-002, EVAL-004 |
| Verification date | 2026-08-26 |
| Verified checkpoint | `659c90336c3230e13c06dcab76e02514b02da74a` |
| Aggregate result | Pass |

## Outcome

COH now routes workflow tool requests through a single narrow
`workflow.ActionAuthority` port implemented by a broker-private authority.
The broker accepts only a strict, canonical `ToolIntent`, resolves actor,
scope, signed manifest, policy, approval, and route context from trusted
state, and owns the only private `connector.Gateway` capability.

Immediately before consequential dispatch, the route verifies the signed
manifest, exact intent binding, active actor authority, fresh pre-dispatch
policy, exact single-use approval, applicable signed ROE, and E-stop state.
It appends an allow audit proof and durably records `dispatching` before the
connector can be called. Provider, workflow, transport, UI, and command
boundaries cannot import connector, executor, runner, credential, or secret
capabilities.

Durable records bind the intent, trusted context, manifest, intent and
pre-dispatch policy decisions, approval, actors, audit events, receipt,
idempotency identity, prior provenance, timestamps, and revision. A completed
replay returns its stored receipt without resolving authority or dispatching.
An indeterminate dispatch becomes `uncertain` after restart and is never
redispatched.

## Short-task completion mapping

| Task | Authoritative evidence | Result |
|---|---|---|
| 1. Freeze route records | `coh.tool-route/v1` JSON Schema, three fixtures, strict public Go record types, canonical serialization | Pass |
| 2. Validate and digest ToolIntent | Required-field and unique-key decoder, unknown/duplicate/missing/trailing/oversize rejection, shared replay-compatible digest, invalid-input test | Pass |
| 3. Build broker-owned authority | Unexported route implementation, trusted-context resolver, private store/stop/gate/connector ports, narrow public `Authority` surface | Pass |
| 4. Recheck fresh authority | Signed-manifest verification, fresh policy decision, exact approval consumption, applicable ROE, two E-stop checks, actor and signer activity validation | Pass |
| 5. Bind one intent to private dispatch | Exact task/case/tool/action/sole-target/argument binding, private connector field and constructor, no generic callback or exported capability | Pass |
| 6. Return receipt and fail-closed audit | Strict `ActionReceipt`, immutable evidence reference, fixed reason codes, pre-dispatch/dispatch/terminal audit records, no raw dependency errors | Pass |
| 7. Enforce public and compile boundaries | Architecture contract, public-surface reflection test, forbidden-import verifier across provider/workflow/transport/UI/command | Pass |
| 8. Handle replay, tamper, stale state, and revocation | Idempotent replay, one-byte change, scope drift, actor revocation, stale policy, approval replay, E-stop, and provenance-tamper tests | Pass |
| 9. Recover without redispatch | Durable pending/authorizing/dispatching/terminal transitions, connector ambiguity handling, crash/restart test proving connector call count remains one | Pass |
| 10. Test and publish evidence | Focused/repeated/race tests, vet/static/architecture/file-size/links, verbose adversarial trace, all 18 clean baseline stages, this report and manifest | Pass |

## Acceptance mapping

| Acceptance criterion | Authoritative evidence | Result |
|---|---|---|
| Every model tool request becomes a broker-validated ToolIntent; no direct provider, skill, UI, or workflow connector route | `ActionAuthority` is the workflow's only action port; broker-private implementation; architecture and forbidden-import checks; no production skill execution package exists outside this port | Pass |
| Default deny, actor/scope binding, redaction, fail-closed audit, replay/tamper/stale/revocation handling | Strict route contract and bindings, fixed reason codes, audit adapter, provenance validation, named adversarial tests | Pass |
| Invalid input, denial, timeout/cancellation, and recovery preserve provenance without bypass | Invalid input is rejected before trusted resolution; denial/cancellation/timeout are typed; post-dispatch ambiguity is uncertain; restart never redispatches | Pass |
| Success and relevant failure tests pass applicable CI, race, architecture, secret, license, and size gates | Focused verifier and all 18 clean baseline stages at the verified checkpoint | Pass |
| Adversarial trace, policy decision, approval/audit proof, and denial/revocation evidence cross-reference CYB-69 and its requirements | Retained focused and verbose logs, durable state/audit assertions, this report and checksum manifest | Pass |

## Contract and trust boundary

The public schema is `contracts/tool/v1/tool-route.schema.json`, file SHA-256
`c4e5e359f2bc4f2f01fe17db4a30cf7271ff548fb4f98bd48a10b5276c9f2010`.
It freezes intent, route state, and receipt records with strict versions,
bounded UUID/token/digest/timestamp fields, explicit required fields, no
unknown properties, and state-dependent authorization and terminal bindings.

Runtime decoding additionally rejects duplicate keys, missing fields,
malformed or trailing JSON, records larger than one MiB, unsupported versions,
invalid tokens/digests/media types, and noncanonical timestamps. The intent
contains only operation and case identity, tool/action tokens, and exact target
and argument digests. It cannot carry a credential, lease, connector,
executor, runner, policy evaluator, signed envelope, raw target, raw argument,
or generic callback. Credential lease acquisition and revocation therefore
remain behind the broker/connector boundary and cannot be model-controlled.

The current pre-dispatch authority admits T2-T4 consequential manifests.
T0-T1 requests still use ToolIntent and are explicitly denied at this boundary
until a separately reviewed low-risk policy exists; they do not gain a bypass.

## Policy, approval, audit, and revocation proof

The success test asserts that one submitted ToolIntent produces exactly one
connector call and a terminal route state containing:

- the fresh pre-dispatch policy decision digest;
- the consumed approval revision and approval fingerprint digest;
- the dispatch audit identifier and completion audit identifier;
- a strict receipt bound to the intent digest; and
- chained provenance covering all immutable and transition fields.

It then replays the same operation and proves the connector and resolver call
counts remain unchanged. The pre-dispatch gate independently verifies the
signed manifest and applicable ROE, reevaluates policy, consumes the exact
approval, rejects replay, and appends its audit proof before returning its
private capability.

Named denial tests prove fail-closed behavior for a changed intent, case-scope
drift, inactive actor, stale policy, consumed approval, E-stop before and after
authorization, unsupported tier, corrupt durable state, canceled context,
expired deadline, audit failure, invalid connector receipt, and ambiguous
connector result. Raw causes such as connector errors are reduced to fixed
reason codes and never enter state, receipts, or audit fields.

## Replay and recovery proof

The stable store key is case plus operation ID; the exact intent and trusted
context digests are immutable. The store performs begin-if-absent and
compare-and-save transitions. Each loaded record is fully validated and its
provenance recomputed before trusted resolution.

The connector becomes reachable only after the dispatch audit succeeds and
the `dispatching` transition is durable. If terminal persistence fails after a
connector call, the retained record remains `dispatching`. A newly constructed
authority loads it, records an `uncertain` terminal receipt, and proves the
connector call count stays one. Connector errors and invalid receipts use the
same conservative recovery rule.

## Focused verification and adversarial trace

The clean checkpoint passed `scripts/verify_broker_tool_routing.sh`. Retained
log:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/broker-route.DKg5C6/broker-route.log
SHA-256 9f74153e72a28754f65c686550557ad0cc743376e0eb8130f5959d41933bcea0
```

The verifier runs focused tests once and three times, race detection, vet,
static analysis, architecture, file-size, link, schema/fixture,
forbidden-import, and diff-hygiene checks. Architecture verification reports
63 packages, zero violations, contract digest
`ea8078bebba2fb77210a7d6f3fda746854dfb1b408b23388c846b7836ce58904`.
Provenance records the exact checkpoint and `modified=false`.

The verbose trace names the strict-decoding, success, replay, policy,
approval, audit, denial, revocation, scope, cancellation, timeout,
connector-ambiguity, and crash/restart cases:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/broker-route.DKg5C6/adversarial-trace.log
SHA-256 ec611cb287bb27d0976469c100fa17c2a038b84a422b0b52610e7de61195339b
```

## Clean baseline

All 18 baseline stages passed with `quality_gate_promotable=true`,
`verification.outcome=passed`, and `vcs_modified=false`:

```text
/Users/aj_lobster/Developer/COH-toolchains/ci-artifacts/baseline/run.fCfdVD/quality-report.json
```

Embedded report digest:
`6f6349c6356c0b05c78dd0af3066ca8281562def7089ebe63ac9caf905d4c58d`.
Report-file SHA-256:
`3eb6261768125d4c374d8bb4173c37642d2f5c8d6b7e15c718556a32851c343a`.
Provenance records 977 source files, source digest
`b6e2df8abd613505fef48f24685624839e402623588c6f869355296168a6aa17`,
Go 1.26.7 on darwin/arm64, and the exact verified checkpoint.

## Reproduction

```sh
./scripts/verify_broker_tool_routing.sh
./scripts/run_ci_quality.sh baseline
```

## Residual scope

- Reconciliation of an `uncertain` external effect is deliberately separate;
  this route never guesses success or risks duplicate execution.
- A future low-risk policy may admit T0-T1 manifests only through a reviewed,
  versioned broker change; current behavior is explicit default denial.
- Incompatible route-contract or recovery changes require a new version and
  migration/replay evidence.
- Independent security architecture review remains the production-release
  gate under CYB-173.
