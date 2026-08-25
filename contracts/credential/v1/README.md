# COH credential-lease issuance contract v1

This broker-internal contract freezes the issuance input for COH-E04-04 and
SEC-012, SEC-024, and SEC-040. A request binds one short-lived credential
lease to an authenticated organization, tenant, case, and actor; one task and
canonical action; an exact sorted target set; one typed operation; one
connector or runner audience; the audience's authenticated transport identity;
and one versioned opaque credential reference.

The request does not prove authority. The broker separately receives current
authenticated actor, authorization, policy, approval, cancellation, safety,
and audience-health snapshots. It must revalidate those snapshots, the current
credential version, lease expiry, and revocation immediately before every
dispatch. Remote audience identity digests bind the lease to the mutually
authenticated transport identity so certificate rotation or revocation makes
an old dispatch snapshot stale.

Lease capabilities and credential values are deliberately absent from this
JSON contract. They are broker-owned, non-serializable values and must never
appear in prompts, logs, traces, workflow history, API responses, diagnostics,
audit payloads, or evidence. Requested lifetimes are positive and capped at
five minutes; the broker may issue a shorter lifetime.

The frozen corpus contains one valid issuance request and 24 adversarial
mutations covering unsupported contracts, missing scope, malformed identity,
target ambiguity, audience tampering, excessive lifetime, secret-bearing
fields, and invalid credential references.
