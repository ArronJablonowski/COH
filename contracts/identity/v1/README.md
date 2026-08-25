# COH local identity and RBAC contract v1

This contract implements the local-workstation portion of COH-E04-01. It fixes
the actor record and common API/CLI authorization-request shapes used by
`internal/domain/localidentity` and the authenticated transport boundary.

Every request carries organization, tenant, case, and actor UUIDv7 identifiers.
No missing or inferred scope is permitted. Actor records carry an Ed25519 public
key, positive revision, active state, independently assignable roles, and exact
tenant/case grants. Private keys, signatures, session tokens, password values,
and raw request bodies are not actor or RBAC decision fields.

## Fixed role permissions

| Role | Permissions |
|---|---|
| Analyst | case read/write, evidence read/write, bounded query, workflow management, action request |
| Approver | case/evidence read, approval decision for T2–T4 |
| Administrator | case read, configuration management, identity management, audit read |
| Auditor | case/evidence/audit read only |
| Service | case/evidence read and service invocation |

Roles are additive but do not imply one another. Administrator does not imply
Approver. Service cannot be combined with a human role. RBAC permission to
request an action does not authorize its execution; signed policy, exact
approval, audit, credentials, and broker controls remain mandatory.

Grants are organization-bound through the actor record, tenant-bound per grant,
and either enumerate sorted case IDs or explicitly select all cases in that
tenant. A request outside any one of those boundaries is denied.

The valid fixtures cover all five roles and both API and CLI channels. The
denial corpus mutates those fixtures to cover absent/crossed scope, invalid
actors, mixed/duplicate roles, unknown permissions, tier contradictions, and
role escalation.
