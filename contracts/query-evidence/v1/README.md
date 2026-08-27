# Query evidence contract v1

`query-evidence-record.schema.json` defines the redacted, immutable provenance
record produced by COH-E12-05. `fixtures/record.canonical.json` is a canonical
genesis record accepted by the strict Go decoder.

The contract intentionally contains no native query text, result rows, vendor
handles, credentials, URLs, encryption key references, ciphertext locators, or
raw dependency errors. `native_query` and optional `result` values are exact
COH-E10 encrypted-evidence bindings. `previous_provenance_digest`, `revision`,
and `transition_id` provide append-only ordering and idempotent recovery.

Compatibility changes to identity, chain rules, events, completeness,
statistics, cancellation, or artifact binding require a new major contract.
