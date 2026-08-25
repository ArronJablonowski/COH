# Domain v1 fixture status

The envelope fixture is a positive schema input. Files under `denied/` are
well-formed JSON that must fail for the named reason without producing canonical
bytes or a persistent object.

The four grouped positive files cover every registered kind.
`payload-denials.json` defines one executable negative mutation for every kind.
Cancellation, timeout, recovery, size, depth, and source-immutability cases are
contextual or generated bounds and therefore live in the Go contract tests.

| Fixture | Expected result |
|---|---|
| `envelope.valid.json` | Common envelope accepted and canonicalized |
| `*-payloads.valid.json` | All 16 registered payload kinds accepted and recover byte-identically |
| `payload-denials.json` | All 16 named per-kind mutations denied |
| `denied/unknown-field.json` | Denied because the common envelope is closed to unknown fields |
| `denied/unsupported-version.json` | Denied because only exact `coh.domain/v1` is registered |
| `denied/bad-timestamp.json` | Denied because canonical timestamps require UTC and nine fractional digits |
