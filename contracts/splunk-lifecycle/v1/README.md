# Splunk search-job lifecycle contract v1

This package freezes the Splunk-specific side of CYB-96 / COH-E14-03. COH's
common query connector contract remains authoritative for public execution,
poll, page, statistics, completeness, and cancellation records.

The fixtures here constrain the external trust boundary:

- `lifecycle-policy.json` fixes asynchronous historical execution, the four
  typed operations, recognized states, page ceiling, poll cadence, and cancel
  confirmation window.
- `sid-ownership.json` proves that a vendor SID is retained only as a digest
  behind an opaque COH handle.
- `job-status.done.json` is the normalized terminal status contract.
- `result-envelope.json` is a bounded finalized-page envelope.
- `cancellation-proof.json` records confirmed cancellation without a SID.
- `denial-corpus.json` and `redacted-error.trace.json` freeze failure coverage
  and the evidence redaction boundary.

Unknown fields, duplicate JSON keys, unsafe state combinations, preview or
real-time modes, truncation, exposed SIDs, native text, result rows, vendor
bodies, credentials, or malformed digests fail closed. Sanitized versioned
vendor recordings are added during lifecycle conformance testing; they cannot
authorize or widen this contract.
