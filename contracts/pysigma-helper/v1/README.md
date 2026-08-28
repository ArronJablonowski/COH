# Signed pySigma helper contract v1

This contract publishes the closed credentialless compiler protocol for
CYB-105 / COH-E15-01 and FR-055, FR-056, SEC-019. The helper accepts one
bounded Sigma 2.1 basic rule, one explicit mapping, one exact candidate backend,
lower policy limits, digests, deadline, and expected helper identity. Actor,
authorization, audit records, credentials, endpoints, executable selection,
environment, paths, and publication state remain in the Go control plane.

`compile-request.schema.json` and `compile-response.schema.json` are the only
process input and output. A successful response is `compiled_untrusted`, never
`supported`: COH-E15-02 must rebind it to current discovered schema and pass the
matching native ES|QL, SPL, or KQL validator.

`capability-snapshot.schema.json` freezes the candidate backend matrix and
records Security Onion as unavailable because OpenSearch Lucene/PPL is not COH
OQL. `helper-attestation.schema.json` binds the signed artifact and exact Python,
pySigma, PyInstaller, package, backend-matrix, and security-control state.
`provenance-receipt.schema.json` links a compiled result to its complete
digest-only authority chain. `denial-corpus.schema.json` and
`redacted-trace.schema.json` publish machine-checkable failure coverage without
revealing source YAML, native queries, field names, paths, or credentials.

The Go handoff keeps every successful helper response in
`compiled_untrusted`. It rebinds the exact mapping to the current discovered
schema before routing query text to exactly one validator identity:
`elastic-esql-1.0.0`, `splunk-parser-1.0.0+native-preflight`, or
`kusto-language-12.4.1-coh-1.0.0`. Only a self-digested, query-free
`native_validated` receipt may cross back. CYB-102 owns the concrete adapters
to those parsers; schema drift or an unsupported conversion invokes none of
them and releases no native query.

All schemas are JSON Schema 2020-12 and closed at every object boundary. The Go
decoder additionally rejects duplicate keys, trailing documents, noncanonical
timestamps, unsorted sets, ambiguous field maps, self-digest mismatch, backend
substitution, partial success, and non-redacted traces. See
`docs/design/signed-pysigma-helper.md` and `compatibility-matrix.md`.
