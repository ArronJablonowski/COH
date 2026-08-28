# Kusto.Language validator contract v1

This contract publishes the closed credentialless helper protocol and the
authority-bearing evidence records for CYB-98 / COH-E14-05 and FR-052, SEC-019.
The helper receives only query, qualified schema, semantic policy, limit,
deadline, and expected helper identity. Actor, authorization, audit, credential,
endpoint, executable, environment, and evidence state remain in the Go control
plane.

`transport-envelope.schema.json` is the native-executor input and contains only
eight bounded, contiguous request chunks. Their concatenation is exactly one
`helper-request.schema.json` document; `helper-response.schema.json` is the only
process output. The helper response is never trusted by decoding alone;
the Go validator recomputes all digests, verifies the signed attestation and
current authority, and commits fail-closed audit before returning an accepted
common query-validation result.

`semantic-registry.schema.json` freezes the exact v1 operator/function policy.
`helper-attestation.schema.json`, `policy-decision.schema.json`,
`audit-proof.schema.json`, and `revocation.schema.json` publish digest-only
identity and control evidence. `denial-corpus.schema.json` binds each prohibited
class to a stable reason and executable test.

The deterministic fixtures include an accepted KQL corpus, a hostile metadata
corpus, and the denial corpus. The pinned managed-runtime test executes every
accepted query and metadata mutation plus every denial case marked
`TestSemanticDenialCorpus`; Go tests cover contract ambiguity, substitutions,
stale state, signature/runtime/package drift, replay and retained-result tamper,
resource exhaustion, timeout/cancellation, outage recovery, audit failure,
redaction, and exact concurrent coalescing.

All schemas are JSON Schema 2020-12, closed at every object boundary, and use
contract version `1.0.0`. Go readers additionally reject duplicate keys,
trailing documents, noncanonical timestamps, unsorted/duplicate sets,
unsupported scalar types, invalid relationships, and self-digest mismatch.
See `docs/design/kusto-language-validator.md` and `compatibility-matrix.md`.
