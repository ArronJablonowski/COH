# Signed tool registry v1

| Field | Value |
|---|---|
| Issue | COH-E06-01 / CYB-53 |
| Requirements | SEC-005, SEC-018 |
| Manifest | `coh.tool-manifest/v1` / `1.0.0` |
| Envelope | `coh.signed-tool-manifest/v1` / `1.0.0` |
| Canonicalization | COH-CJ-1 |
| Signature | Ed25519 over `COH-SIGNED-TOOL-MANIFEST-V1\0 || canonical_manifest` |

The registry admits an exact tool name/version only after canonical schema
validation, review approval, current validity, and verification against a fresh
active approved publisher authority. Exact admission replay recovers the same
entry; changed bytes for an existing name/version conflict and never replace
the last valid snapshot.

Every manifest binds the immutable executable or recipe digest, tool-wide tier
ceiling, publisher, review and threat-model provenance, validity, and a sorted
operation set. Each operation binds a strict typed-input schema, baseline and
maximum tier, isolation class, credential classes, finite resource limits,
network policy, cancellation behavior, and retry behavior.

Runtime policy supplies a capability ceiling at resolution. It may select the
signed ceiling or a lower tier. A value above either the tool or operation
ceiling is an attempted authority expansion and is denied. A required tier
below the signed baseline is also denied; contextual classification cannot
relabel an operation as safer than its reviewed baseline.

Raw credentials, target values, arguments, payloads, private keys, policy
source, review notes, prompts, and free-form descriptions have no field in the
contract. Exact action-specific values remain in the signed action manifest.

The registry re-verifies stored envelope bytes and fresh publisher authority on
every resolution. Publisher removal, key rotation/revocation, approval rollback,
manifest expiry, digest change, or schema drift therefore fails closed without
process restart.

## Broker-only route records

`tool-route.schema.json` freezes `coh.tool-route/v1` ToolIntent and
ActionReceipt records for CYB-69 / COH-E08-03. The intent contains only one
operation, tenant/case scope, allowlisted tool/action tokens, and exact target
and argument digests. The receipt contains only the intent digest, typed
outcome, and immutable evidence metadata. Neither record has a credential,
secret, raw payload, connector, executor, runner, policy evaluator, or generic
callback field.

The same schema also freezes the redacted durable route state: trusted-context,
manifest, policy, approval, actor, idempotency, transition, audit, receipt, and
provenance digests plus typed status and reason. It has no raw signed envelope,
approval content, credential, connector payload, or free-form error.

The Go decoder requires every field and rejects duplicate, unknown, missing,
trailing, malformed, oversized, or unsupported-version input. The shared
intent digest retains the existing durable agent-loop v1 domain and canonical
preimage so moving validation into the domain contract is replay compatible.
