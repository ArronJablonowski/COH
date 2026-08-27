# Temporal time domain

This package implements CYB-82 / COH-E11-02, FR-024, and EVAL-017. It keeps
source text, parser/tzdata identities, timezone and DST facts, precision,
signed clock skew, conservative inclusive uncertainty, evidence state,
completeness, ordering confidence, audit, provenance, and idempotency bound to
the same case and immutable COH-E10/CYB-80 source identities.

`StrictParserRegistry` accepts only immutable registered identities and closed
format tokens. It has no dynamic layout or fallback parser. A
`PinnedTimezoneResolver` is constructed from locations loaded by trusted
assembly code from a verified tzdata bundle and accepts only the exact supplied
version and digest. It never loads a zone from a path, host default, or network.

`Service.Normalize` writes the command boundary first, returns a durable exact
receipt on replay, denies a changed command under the same idempotency key, and
atomically commits the record, receipt, audit, and provenance values. A store
returns `acquired=false` while an identical operation owns the lease; after a
process restart it may reacquire a stale begun operation and resume it. A lost
commit response is recovered by loading the already durable receipt.

Cancellation and timeout become explicit terminal receipts using a short
non-cancelled persistence context. This does not continue normalization work;
it records only the closed outcome and provenance. Storage failure still
returns `unavailable` and must be reconciled through the begun command.

`CompareRecords` uses inclusive intervals. It returns strict order only for
disjoint bounded intervals, and reports the uncovered nanoseconds between them.
Intersecting intervals remain `overlap`; unbounded or unresolved inputs remain
`unknown`; matching deduplication bindings take duplicate/conflict precedence.

The contract and compatibility rules are in `contracts/time/v1`; migration,
recovery, rollback, and privacy rules are frozen in
`docs/design/time-precision-and-uncertainty.md`. Rollback stops new writes while
retaining the v1 reader and records. It never rewrites evidence or normalized
time history.

