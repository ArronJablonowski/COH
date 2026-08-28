# Generated architecture catalog contract v1

| Field | Value |
|---|---|
| Stable key | COH-E25-05 / CYB-185 |
| Contract version | `1.0.0` |
| Requirements | NFR-019, NFR-026, NFR-027, EVAL-004, EVAL-029 |
| Publication limit | 8 MiB per catalog; 131,072 records |

The catalog generator derives six deterministic, machine-readable inventories
from reviewed declarations and the complete Go source graph. Every output binds
each input to its repository-relative path, exact declared version, and SHA-256
digest. Records and attributes are lexically ordered and the catalog digest is
computed over the canonical compact JSON document with an empty digest field.

The checked-in outputs under `docs/architecture/catalogs` are release evidence.
`scripts/check_architecture_catalogs.sh` regenerates them in a temporary
directory, compares exact bytes, validates publication bounds and links, and
then runs adversarial conformance mutations. Any stale output, undeclared or
orphan capability edge, dependency cycle, alternate `package main`, authority
bypass, model-surface event without a projection rule, or dynamic loader denies
the architecture gate.

Catalog records contain identifiers and bounded structural metadata only. The
generator rejects absolute/private paths, control characters, secret-bearing
attribute names, symlinks, files larger than 8 MiB, unknown declaration fields,
and unsupported versions. It never emits source content, environment values,
credentials, prompt text, evidence payloads, or executable objects.
