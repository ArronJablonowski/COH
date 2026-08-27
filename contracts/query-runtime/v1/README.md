# Governed query runtime contract v1

This bundle defines strict redacted records for the CYB-87 runtime broker:

- `session` is the immutable, digest-chained budget and completeness state;
- `slice_plan` contains exact contiguous UTC descriptors but grants no execution authority; and
- `rate_reservation` proves that the authoritative tenant/source/actor/profile rate gate accepted one exact external operation.

Session identity binds the CYB-85 query and execution digests, CYB-84 bounds
decision, effective limits, cumulative usage, status, handle digests, last page
and rate digests, cancellation intent, vendor provenance, revision, and time.
Records contain no native query text, result rows, credential, URL, raw handle,
or dependency error.

Domain-separated SHA-256 digests use canonical JSON and the domains
`COH-QUERY-RUNTIME-SESSION-V1`, `COH-QUERY-SLICE-PLAN-V1`,
`COH-QUERY-SLICE-V1`, and `COH-QUERY-RATE-RESERVATION-V1`, each followed by a
NUL byte. Unknown fields and versions fail closed. Semantic changes require a
new major contract and migration evidence.
