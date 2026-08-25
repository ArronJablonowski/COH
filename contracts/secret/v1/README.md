# COH opaque secret-reference contract v1

This contract implements the configuration and broker-input portion of
COH-E04-03. Configuration stores only `coh.secret-reference/v1` objects naming
an approved backend, opaque entry identifier, and positive expected version.

A reference cannot contain a secret value, path, URL, environment variable,
command, token, password, credential, or backend connection detail. Inline,
environment, command, and URL backends are semantically forbidden. Entry IDs
are bounded tokens rather than filesystem paths.

Resolution requests are broker-internal and bind the reference to a UUIDv7
request, idempotency key, organization, tenant, case, actor, canonical action
digest, and credential class. The backend supplies trusted scope and current
version metadata separately; fields inside the request never prove authority.

The native protected-file adapter and deterministic sealed-memory test adapter
use this same provider-neutral reference shape. Server/vendor adapters can be
registered later without adding secret-bearing configuration fields.

The frozen fixtures contain two valid references, two valid scoped requests,
and an adversarial corpus covering secret-bearing fields, forbidden backends,
path/URL injection, absent scope, malformed digests, stale versions, and
unsupported contracts.
