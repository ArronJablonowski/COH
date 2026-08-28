# Sentinel bounded query v1 compatibility

| Component | Accepted v1 identity | Change requiring requalification |
|---|---|---|
| Common query | `coh.query-*/v1`, contract `1.0.0` | digest, time, limit, lifecycle, or completeness semantics |
| Discovery | `coh.sentinel-discovery-config/v1`, Azure Logs `v1` | workspace, endpoint, audience, TLS, metadata, or qualification identity |
| Validator | `kusto-language-12.4.1-coh-1.0.0` | helper, registry, AST rewrite, schema, output, or audit identity |
| Query runtime | `coh.sentinel-query-runtime-config/v1` | route, request/response, stable-key, timeout, limit, or error policy |
| Slice planner | `coh.sentinel-slice-plan/v1` | timestamp precision, midpoint, threshold, ordering, retry, or cancellation rule |
| Evaluation | `coh.sentinel-slicing-*/v1`, corpus `1.0.0` | fixture, task, trial, grader, threshold, environment, or artifact identity |

Readers accept exact versions only and reject unknown fields. Adding an
optional field is still a contract revision because closed JSON is deliberate.
Migration creates new records with lineage and reruns the complete locked
corpus. Rollback disables Sentinel execution and restores a separately signed,
qualified version; it never reuses cached credentials, responses, results,
validator admissions, or evidence as current authority.
