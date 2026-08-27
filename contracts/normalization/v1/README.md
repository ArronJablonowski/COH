# COH normalization envelope contract v1

| Field | Value |
|---|---|
| Issue | COH-E11-01 / CYB-80 |
| Requirements | FR-021, FR-022 |
| Contract | `1.0.0` |
| Envelope | `coh.normalized-event-envelope/v1` |
| Canonicalization | `COH-NJ-1` |
| OCSF | `1.9.0` / `856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba` |
| ECS | `9.5.0` / `401807e0547301525acd28c4fb667203fec66d59` |

The contract keeps three distinct representations:

- the COH-E10 immutable raw artifact and manifest references;
- the canonical original vendor fields observed at ingestion;
- the OCSF-first normalized event plus an explicit nullable ECS projection.

None can be reconstructed from another and none may be silently dropped. The
normalization record binds the exact mapping set, normalizer binary, coverage,
unmapped vendor paths, and transformation digest. The lineage record binds the
raw artifact, manifest, ingestion receipt, provenance, and any parent
envelopes within the same case.

The schema closes every COH-owned object. OCSF, ECS, and original field maps
remain extensible only inside their named bounded containers because their
vocabularies are external or source-defined. The Go validator additionally
enforces canonical section digests, sorted schema-declared sets, nesting and
value-size limits, cross-field coverage rules, classification monotonicity,
and exact compatibility targets.

`COH-NJ-1` preserves fixed-decimal telemetry values without converting them to
binary floating point. It forbids exponent notation, negative zero,
insignificant leading zeroes, and insignificant trailing fractional zeroes.
This keeps numeric values lossless and uniquely encoded while preserving the
existing `COH-CJ-1` rules for objects, arrays, strings, booleans, nulls, and
integers.

A dataset locator is optional. When present, it identifies a partitioned
Parquet artifact and logical row only through immutable artifact and manifest
digests. It contains no path or URL. Dataset bytes are available only through
the bounded, context-aware Go `DatasetReader` port.

See [the design freeze](../../../docs/design/normalized-event-envelope.md) and
[the compatibility matrix](compatibility-matrix.md).
