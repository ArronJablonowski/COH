# Broker-only tool routing

| Field | Value |
|---|---|
| Issue | COH-E08-03 / CYB-69 |
| Requirements | FR-018, SEC-002, EVAL-004 |
| Contract | `coh.tool-route/v1` / `1.0.0` |
| Boundary | `internal/broker` |

## Decision

Every workflow-side tool request is a strict `domain.ToolIntent`. The workflow
can submit it only through its narrow `ActionAuthority` port. The only concrete
implementation is an unexported broker type. It owns the sole private
`connector.Gateway`; providers, workflows, transports, UI assets, and command
logic cannot import or receive that capability.

The model controls none of the actor, policy, approval, signer, E-stop, route,
or connector authority. A broker-private resolver obtains that context from
trusted state and the broker verifies the signed action envelope itself. The
intent must exactly match the signed workflow task, tenant/case, tool,
operation, sole target digest, and argument digest.

## Dispatch order

One consequential route follows this order:

1. Strictly validate and canonically digest the ToolIntent.
2. Load any existing durable route state by case and operation ID.
3. Return a completed replay, deny changed intent bytes, or convert an
   unresolved `dispatching` record to `uncertain` without calling a connector.
4. Resolve and digest trusted actor, signed-manifest, policy, approval, and
   route context.
5. Persist `pending`, then `authorizing`, before the policy/approval gate.
6. Check E-stop state, reverify the signed action, evaluate fresh
   pre-dispatch policy, consume the exact approval, verify applicable ROE, and
   append the pre-dispatch audit proof.
7. Recheck E-stop state, append a route-dispatch audit event, and persist
   `dispatching` with the policy and approval proof digests.
8. Invoke the private connector exactly once.
9. Validate the broker receipt, append a terminal audit event, and persist the
   typed receipt and chained provenance.

No connector call occurs if validation, authority resolution, policy,
approval, ROE, E-stop, audit, or the durable `dispatching` save fails.
The current pre-dispatch authority admits only consequential T2-T4 manifests;
T0-T1 requests still enter through ToolIntent and are explicitly denied at the
broker boundary until a separately reviewed low-risk policy is introduced.

## Replay and recovery

The stable idempotency identity is tenant/case plus operation ID. The exact
intent digest and trusted-context digest are immutable after the initial
record. Completed replays return the stored receipt without re-resolving
authority or calling the connector. A changed intent for the same operation is
denied and audited.

If a process stops after `dispatching` but before a validated receipt is
durable, restart records `uncertain`; it never redispatches. Connector errors
and malformed receipts are treated the same way because an external effect may
already have occurred. Safe failures before dispatch retain denial,
cancellation, timeout, or unavailable semantics.

Every state carries its previous provenance digest. Load validation recomputes
the current transition digest over all actor, scope, policy, approval,
idempotency, audit, receipt, status, reason, timestamp, and revision fields.
Valid-looking state changes therefore fail closed before trusted resolution.

## Redaction and audit

The public contract contains only UUIDs, bounded tokens, revisions,
timestamps, typed outcomes, and SHA-256 references. It has no prompt, target
value, argument value, signed-envelope bytes, credential, policy source,
approval content, connector payload, executor handle, runner lease, generic
callback, or free-form error.

Audit records contain the stable operation and actor identities plus sorted
digests for the intent, trusted context, manifest, intent/pre-dispatch policy
decisions, approval fingerprint, dispatch proof, receipt evidence, and
provenance. Dependency errors are reduced to fixed reason codes; raw errors are
never copied to the receipt, durable state, or audit event.

## Enforcement

- The architecture contract permits connector imports only inside the broker
  and connector boundaries.
- A source verifier rejects connector, executor, runner, credential, or secret
  imports from workflow, provider, transport, and UI boundaries.
- Broker public-surface tests reject exported connector or policy capability
  types and verify the route constructor and connector field remain private.
- Runtime adversarial tests cover intent tamper, actor revocation, stale
  policy, approval replay, scope drift, unsupported low-risk tiers, E-stop
  before and after authorization, corrupted state, cancellation, timeout,
  audit failure, invalid receipt, connector ambiguity, crash/restart, and
  idempotent replay.

`scripts/verify_broker_tool_routing.sh` runs these controls with repeated and
race tests plus vet, static analysis, architecture, file-size, link, and diff
checks.
