# Sentinel bounded query contract v1

This contract publishes the closed query-runtime records for CYB-100 /
COH-E14-06 and FR-052, FR-054, EVAL-016. It extends the separately frozen
Sentinel discovery contract without changing CYB-97 evidence.

`sentinel-query-contracts.schema.json` defines runtime configuration, stable-key
profiles, typed POST requests, strict result/error/statistics responses,
transport receipts, and deterministic slice plans. Every top-level record uses
contract version `1.0.0`, a distinct `coh.sentinel-*/v1` schema version, and a
domain-separated self-digest. Go readers additionally reject duplicate JSON
keys, unknown fields, noncanonical timestamps, invalid row types, nonfinite
numbers, relationship violations, oversize documents, and digest mismatch.

The request route, credential lease, and TLS checks remain implementation-only;
the public record contains no bearer token, endpoint, header map, vendor URL,
or generic transport option. Canonical KQL is present only at the private typed
transport boundary and is excluded from public errors and evaluation evidence.

`fixtures/vendor` contains sanitized documented response shapes. They are
inputs, never qualified live-vendor evidence. In particular, HTTP 200 with
`error.code=PartialError` is a failure fixture and none of its accompanying
tables may enter a COH result page.

`fixtures/denial-corpus.json` locks the public adversarial classes to executable
test names. `compatibility-matrix.md` records version and migration rules. See
`docs/design/sentinel-slicing-evaluation.md` for authority, slicing, dedupe,
cancellation, evaluation, and rollout semantics.
