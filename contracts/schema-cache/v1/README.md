# Bounded schema-cache contract v1

This contract defines the canonical, redacted identity input for an in-memory
COH schema-cache entry. Its domain-separated SHA-256 digest is returned by the
Go cache as `Snapshot.IdentityDigest()`.

The identity binds the organization, tenant, source, exact resource-scope
digest, capability digest, adapter version, connector schema version, immutable
schema-page digest, vendor schema digest, provenance digest, insertion time, and
effective expiration. It contains no case, actor, query text, result, credential,
URL, continuation token, or raw vendor error and grants no authority.

The digest domain is `COH-SCHEMA-CACHE-ENTRY-V1` followed by a NUL byte and the
RFC 8785-style canonical JSON bytes enforced by COH's domain-contract helper.
Changing any field or its meaning requires a new major schema version.
