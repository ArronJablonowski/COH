# Server OIDC authentication and scoped RBAC

## Purpose

CYB-174 supplies the authentication boundary required by the `native_server`
and `compose` deployment profiles. It accepts a pinned OIDC identity assertion,
maps its immutable issuer/subject pair to a current COH actor, issues a
short-lived opaque session, and re-evaluates current actor and signing-key
authority before every request.

The OIDC contract is `coh.server-oidc/v1` / `1.0.0`. It does not discover an
issuer, accept caller-selected JWKS URLs, perform dynamic client registration,
or provide a local-auth fallback for a server profile.

## Audited profile composition

`command.ComposeServerOIDC` first runs the deployment-profile validator with
the authenticated change-authority snapshot and mandatory profile audit sink.
It composes no authentication service unless the resulting decision is
allowed, names `native_server` or `compose`, requires OIDC and mTLS, and exactly
matches both the provider profile kind and provider profile-decision digest.

The composition root requires explicit actor, login-state, session, replay,
key-source, and authentication-audit ports. A missing port, invalid provider,
wrong profile, changed decision, or failed profile audit returns no service.

## Login authority

Login begins with an exact organization and one configured audience. The
service creates independent 128-bit state and 256-bit nonce values, stores only
the nonce digest with the exact issuer, audience, profile kind, and profile
decision, and durably audits issuance. An audit failure consumes the state and
returns no usable login response.

Completion atomically consumes state before parsing a compact JWT. The JOSE
header has exactly `alg`, `kid`, and `typ`; unknown, duplicate, or trailing
fields deny. `typ` must be `JWT`, the algorithm must be on the frozen provider
allowlist, and the key must be found through the configured opaque JWKS source
reference for the exact issuer and key ID.

The implementation supports Ed25519/EdDSA, P-256/ES256, and 2048-bit-or-larger
RSA/RS256 with exponent 65537 or greater. It denies `none`, algorithm/key-type
substitution, unknown or inactive keys, invalid signatures, and keys outside
their validity interval.

Claims require exact issuer, one selected audience, organization, login nonce,
and bounded token time. The immutable issuer/subject lookup returns the current
COH actor. Token actor, roles, and sorted tenant assertions must exactly match
that actor at login; otherwise the assertion is stale or crossed and denies.

## Sessions and per-request authorization

Successful login generates independent session-ID and 256-bit bearer material.
Only `sha256(token)` is stored. The issued object serializes only its session ID
and expiry, exposes token bytes through a bounded callback, supports explicit
destruction, and never places the token in JSON, audit, workflow, or evidence.
The session lifetime is capped by both the configured maximum and token expiry.

Every request validates the complete local-identity request and then checks:

1. opaque session token, digest, profile decision, expiry, and revocation;
2. exact request organization and actor;
3. current signing-key presence, active state, revision, algorithm, and time;
4. current actor presence, active state, identity, and revision;
5. tenant/case grant, role permission, and action tier through the shared RBAC
   evaluator; and
6. atomic binding of `(session ID, idempotency key)` to the complete request
   digest.

An exact retry is marked replayed. Any changed request under the same key is a
conflict. Actor or key rotation/revocation invalidates an existing session on
its next request without waiting for expiry.

## Failure, audit, and redaction

Authentication and authorization use closed error/outcome enums. Raw tokens,
claims, nonce, subject, key ID, key material, token digest, backend error, and
request body are absent from events and decisions. Subject, issuer, and key ID
appear only as SHA-256 digests where correlation is required.

Login, completion, revocation, and every authorization outcome require audit.
Audit runs in a cancellation-independent bounded context so caller
cancellation cannot suppress the decision record. Audit failure returns
`unavailable`; completion revokes the newly stored session before returning,
and authorization can never return an allowed decision when its audit append
fails.

## Verification

Run:

```sh
./scripts/verify_server_oidc.sh
```

The verifier checks both strict schemas, valid fixtures, all 24 frozen contract
denials, unit/race/vet coverage, the source-surface guard, server/Compose
composition, and the repository architecture contract.

## Residual scope

- The in-memory stores provide deterministic atomicity for local verification;
  multi-replica deployment requires durable shared implementations of state,
  session, and replay ports.
- A production JWKS adapter owns bounded retrieval, caching, certificate trust,
  and refresh. This boundary accepts only pinned, validated `KeyRecord` values
  from that port and performs no network access itself.
- Browser redirect/callback routing and secure session-cookie transport belong
  to the future HTTP adapter. The service already supplies one-time state,
  nonce, and opaque session semantics for that adapter.
- Independent security architecture review remains required before the first
  production release.
