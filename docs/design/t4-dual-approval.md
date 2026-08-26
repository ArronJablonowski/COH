# T4 dual approval

| Field | Value |
|---|---|
| Issue | COH-E05-05 / CYB-48 |
| Requirements | FR-005, SEC-007, EVAL-007 |
| Lifecycle contract | `coh.approval-lifecycle/v2` / `2.0.0` |
| Threshold | Exactly two distinct enrolled human principals |

## Control

T4 is unavailable until two grants exist for the same exact CYB-50
fingerprint. Neither grant may come from the requestor actor, the requestor's
stable human principal under another account, a service identity, an
unenrolled identity, or the same human principal twice.

The broker derives the threshold from the freshly verified signed action
manifest. Callers, workflows, models, and transports cannot provide or lower a
threshold. A T4 request begins in `requested`; its first valid grant produces a
new audited `requested` revision; its second distinct valid grant alone
produces `granted`.

## Identity and enrollment authority

An actor ID identifies an account. A principal ID identifies the stable human
behind one or more accounts. Fresh enrollment authority contains:

- actor ID and current actor revision;
- stable principal ID;
- identity kind (`human` or `service`);
- current enrollment revision; and
- enrolled state.

The authority must match the independently authenticated broker actor snapshot.
The actor must be active, exact-scope, hold the `approver` role, and hold
`approval.decide`. The identity kind must be `human`, enrollment must be
current, and neither actor nor principal may match the requestor or a prior
grant. Administrator status does not imply Approver and cannot waive any rule.

The persisted grant records actor/principal identities and both authority
revisions. This is safe provenance, not a bearer capability.

## Consumption and revocation

Consumption requires the exact action owner, current fingerprint proof, and
fresh enrollment authority for both stored grants in their append order. Each
current authority must retain the stored actor/principal identity and have
actor and enrollment revisions no older than the grant. Role loss, permission
loss, scope change, actor revocation, unenrollment, principal reassignment,
stale revision, or a missing authority denies before the use counter changes.

Explicit lifecycle revocation remains terminal. Expiration, consumption, and
rejection are also terminal. Enrollment does not create or retroactively grant
an approval: it only makes a human eligible to submit a new grant transition.

## Concurrency, retry, and audit

Two first-grant attempts against the same revision serialize through the
lifecycle compare-and-swap. Exactly one commits and the other conflicts; the
record remains requested with one grant. A later second grant must authorize
against the new revision. Exact retry of either committed grant recovers the
same revision; changed retry input conflicts.

Every successful partial or final grant commits its record revision and audit
outbox reference atomically. Every denied attempt reaches the redacted
fail-closed audit sink. Cancellation, timeout, storage conflict, enrollment
failure, fingerprint mismatch, and audit outage cannot produce usable T4
authority.

## Migration and compatibility

Lifecycle v1 records do not contain action tier, stable principal IDs, or
enrollment revisions and are therefore never accepted as T4 authority. They
must be re-requested under v2. The migration changes the registered canonical
approval payload; no SQLite or PostgreSQL DDL change is required because both
adapters already store versioned generic approval records and transactional
outbox references.

The adversarial corpus is
[`t4-denial-corpus.json`](../../contracts/approval/v1/fixtures/t4-denial-corpus.json).
The dedicated verifier exercises two-person success, partial unavailability,
actor and principal aliasing, service/unenrolled/revoked authority, fresh
consumption checks, concurrent grants, race, architecture, and file size.
