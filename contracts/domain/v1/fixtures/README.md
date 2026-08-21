# Domain v1 fixture status

The envelope fixture is a positive schema input. Files under `denied/` are
well-formed JSON that must fail for the named reason without producing canonical
bytes or a persistent object.

These fixtures cover only the common-envelope slice. Per-kind positive fixtures,
duplicate-key detection, bounds, digest mismatch, cancellation, and recovery
fixtures remain required before CYB-36 is complete.

| Fixture | Expected result |
|---|---|
| `envelope.valid.json` | Common envelope accepted; per-kind `case` validation is not yet claimed |
| `denied/unknown-field.json` | Denied because the common envelope is closed to unknown fields |
| `denied/unsupported-version.json` | Denied because only exact `coh.domain/v1` is registered |
| `denied/bad-timestamp.json` | Denied because canonical timestamps require UTC and nine fractional digits |
