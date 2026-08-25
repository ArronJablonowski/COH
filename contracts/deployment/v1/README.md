# COH deployment-profile contract v1

`deployment-profile.schema.json` defines the complete startup declaration
accepted by the CYB-42 validator. The contract carries only security posture,
service identities, immutable digests, and configuration references. It has no
field for a credential or secret value.

The JSON Schema fixes structure and primitive constraints. The Go validator in
`internal/domain/deploymentprofile` owns the cross-field security rules:

- every change is bound to an organization, administrator actor, monotonic
  revision, and previous configuration digest; the trusted authentication
  snapshot must match before startup can proceed;

- native workstation is macOS arm64, loopback-only, SQLite, persistent Temporal
  development mode, local evidence, local authentication, and Docker-independent;
- native server is Linux amd64 with PostgreSQL 18, production Temporal, OIDC,
  mTLS, a configured evidence store, and three distinct service identities;
- Compose requires the complete six-image inventory by digest, migrations,
  validators, a selected provider, and no Docker socket, public data services,
  or secrets in environment variables;
- connected modes require explicit endpoint references; and
- air-gap mode permits no DNS, Internet, telemetry, update, or external-time
  route and requires the complete signed offline bundle inventory.

Validation does not inspect the host, contact Docker, load a secret, qualify a
platform, or start a service. Passing means only that the declaration is
internally safe and consistent enough to proceed to later composition and
qualification gates.

The high-level `Validator` requires a durable audit sink. It records a redacted,
digest-bound decision for success, invalid input, denial, cancellation, and
timeout. It rejects an inactive actor, scope mismatch, stale revision, changed
lineage, and changed-input replay. An identical current revision and digest is
an explicit idempotent replay. If audit append fails, validation returns
`unavailable` and cannot authorize composition.

Fixtures under `fixtures/valid` cover every deployment and connectivity mode.
`fixtures/denial-corpus.json` applies named mutations to those bases and fixes
the required typed outcome and safe reason code.
