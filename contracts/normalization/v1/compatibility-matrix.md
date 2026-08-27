# Normalized event envelope v1 compatibility matrix

| Change or input | v1 decision | Required action |
|---|---|---|
| Exact envelope `1.0.0`, OCSF `1.9.0`, ECS `9.5.0`, and frozen target-manifest digest | Compatible | Validate all invariants and section digests. |
| Patch-level envelope reader fix that does not change accepted canonical bytes | Compatible after corpus replay | Publish the implementation revision; keep contract `1.0.0`. |
| New optional COH envelope field | Incompatible with v1 closed schema | Publish a new envelope schema version and migration decision. |
| OCSF or ECS release, tag, commit, or source-archive change | Not automatically compatible | Freeze a new target manifest, replay corpora, assess migration, and retain the old reader. |
| Upstream development branch or floating `latest` target | Denied | Select an immutable release tag and commit. |
| Unknown COH-owned field, duplicate key, trailing data, exponent/non-canonical decimal, malformed UTF-8, oversized/deep value | Denied | Correct or explicitly migrate the producer. |
| Unknown source, OCSF, or ECS field inside its bounded named map | Preserved | Retain canonical value; mapping registry determines semantic handling. |
| Missing original field map, raw artifact, manifest, receipt, or provenance reference | Denied | Recover the immutable source bindings before normalization. |
| ECS projection absent | Compatible only as explicit `null` | Preserve all original fields and record coverage/unmapped paths. |
| OCSF/ECS/original section digest mismatch | Denied | Recompute from the authoritative input; do not rewrite history. |
| Weaker envelope or dataset classification than raw evidence | Denied | Raise classification or obtain a separately governed derived artifact. |
| Direct dataset path, URL, SQL, HTTP client, or connector handle | Denied by public contract | Resolve opaque artifact identity through `DatasetReader`. |
| Existing v1 record after an upstream upgrade or rollback | Read-compatible | Retain v1 reader and its exact target manifest; never relabel in place. |
