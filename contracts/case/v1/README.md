# COH case lifecycle contract v1

| Field | Value |
|---|---|
| Issue | COH-E10-01 / CYB-76 |
| Requirements | FR-002, FR-028, SEC-014, SEC-015, SEC-037 |
| Contract version | `1.0.0` |
| Schema | `case-lifecycle.schema.json` |

## Records

The schema freezes five strict, closed record types:

1. `coh.case-command/v1` carries one of the nine closed operations and every
   organization, tenant, case, actor, policy, revision, idempotency, and
   deadline field needed to reject missing context.
2. `coh.case-authorization/v1` binds the command and exact current lifecycle
   facts supplied to the independent authority.
3. `coh.case-decision/v1` binds allow or deny to the authorization digest,
   current revocation state, scope, actor, operation, policy, revision, and
   short validity window.
4. `coh.case-lifecycle/v1` is the current durable case metadata record with
   retention, legal hold, export, tombstone, audit, and provenance state.
5. `coh.case-receipt/v1` is the immutable idempotency receipt containing the
   exact lifecycle command, resulting record, and authorization and audit
   bindings needed for deterministic crash recovery.

Every object rejects additional properties. Optional operation-specific
values are explicit JSON `null`, never omitted or represented by magic empty
strings. Go semantic validation additionally requires exactly the fields for
the selected operation and denies every inapplicable non-null field.

## Closed values

- Operations: `create`, `classify`, `assign`, `place_hold`, `release_hold`,
  `close`, `reopen`, `export`, and `delete`.
- States: `open`, `closed`, and `deleted`.
- Classifications, least to most restrictive: `public`, `internal`,
  `confidential`, and `restricted`.

Reducing classification is not a lifecycle operation. Governed redaction in
COH-E10-04 must create a derived artifact and obtain its own authority; it
cannot silently relabel a case or its source evidence.

## Content and authority exclusion

The contract contains case metadata and immutable digests only. It has no raw
evidence, artifact bytes, prompt, instruction, secret, credential, token,
policy source, approval grant, connector, executor, executable command, shell,
URL, HTTP, callback, or arbitrary payload field. A case command cannot perform a side
effect outside the lifecycle controller and its narrow authority, audit, and
guarded storage ports.

## Retention and deletion

`delete` writes a `deleted` tombstone with a reason digest and deleting actor.
It is rejected while legal hold is active or before `retain_until`. The
current record, receipt, provenance chain, and tamper-evident audit remain
durable. Physical evidence disposition and signed lifecycle bundles remain
separate COH-E10 capabilities and cannot reinterpret a tombstone as permission
to erase audit or custody history.

## Compatibility

Readers and writers require exact schema and contract versions. Unknown,
missing, duplicate, trailing, malformed, or non-canonical fields fail closed.
The generic guarded metadata stores need no DDL migration. Older binaries do
not understand the `case_lifecycle` kind and must reject it rather than mutate
or delete it.
