# COH server OIDC identity contract v1

This contract closes COH-E04 server-profile identity acceptance. Native-server
and Compose request boundaries pin an HTTPS issuer, one or more exact
audiences, an ordered allowlist of `RS256`, `ES256`, and/or `EdDSA`, an opaque
JWKS source reference, mTLS transport, the validated deployment-profile
decision digest, maximum token age, and clock skew.

The frozen token-claim shape contains standard issuer, immutable subject,
audience, issued/not-before/expiry times, JWT ID, and login nonce plus exact COH
organization, actor, role, and tenant assertions. Claims establish an identity
assertion only. The current actor directory remains authoritative for active
state, revision, roles, tenant/case grants, and permissions on every request;
any assertion/directory mismatch denies.

Raw compact tokens, decoded claim bytes, signing keys, login nonces, and opaque
session tokens are never configuration, workflow, decision, audit, log, trace,
API-response, or evidence fields. The provider and claim fixtures use inert
identifiers and contain no bearer credential.

The adversarial corpus contains 24 mutations covering unpinned/unsafe issuer,
audience, algorithm, JWKS and mTLS configuration; malformed temporal or
identity claims; role/tenant ambiguity; and secret-bearing unknown fields.
