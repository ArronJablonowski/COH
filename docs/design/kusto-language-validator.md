# Kusto.Language validator helper design

| Field | Decision |
|---|---|
| Issue | CYB-98 / COH-E14-05 |
| Requirements | FR-052, SEC-019 |
| Upstream parser | `Microsoft.Azure.Kusto.Language` 12.4.1 |
| Build/runtime | .NET SDK 10.0.400; .NET runtime 10.0.11 LTS; `net10.0` |
| Native RIDs | `osx-arm64`, `linux-x64`, `linux-arm64` |
| Tool operation | `kusto.validate` |
| Action tier | T0, credentialless, read-only, `network:none` |
| Security decision | Official semantic parser inside the existing signed native-executor boundary; COH policy remains authoritative |

## Purpose and authority

The helper parses and semantically analyzes one historical KQL tabular
expression against the exact qualified Sentinel workspace schema from CYB-97.
It rejects every syntax, symbol, operator, function, parameter, or statement
outside a closed v1 profile and returns an AST-derived query with a terminal
literal `take` no larger than the admitted row limit.

The helper is a parser and compiler, not an authority. The Go validator owns
actor, organization, tenant, case, source, workspace, resource, capability,
schema, policy, limit, time, audit, replay, revocation, and provenance checks.
The query broker and later Sentinel execution adapter independently recheck
current authority before dispatch. An accepted helper result never grants a
credential, network route, query permission, or reusable approval.

## Pinned supply chain and packaging

The helper source pins `Microsoft.Azure.Kusto.Language` 12.4.1 with a checked-in
NuGet lock file. Restore runs in locked mode from the approved NuGet source,
verifies the repository signature and package digest, and denies preview,
floating, downgraded, additional, or transitively changed packages. `global.json`
pins SDK 10.0.400 with roll-forward disabled. The project pins runtime 10.0.11,
uses deterministic and continuous-integration builds, and treats warnings as
errors.

Each supported RID is published as a self-contained single-file executable.
The release pipeline records the complete package closure, compiler and runtime
identity, artifact digest, SPDX or CycloneDX SBOM, SLSA-compatible provenance,
and reproducibility result. COH admission means an exact executable digest in a
COH Ed25519-signed tool manifest under the current reviewed publisher authority.
The NuGet repository signature is a build-input check; it does not replace the
COH artifact signature. Platform code signing or notarization may be added by a
distribution profile but is not accepted as helper authority.

The helper is disabled unless its exact RID, runtime, package closure, artifact,
manifest, operation, and qualification evidence match. There is no compatible
version range or fallback binary.

## Process trust boundary

The existing `nativeexecutor` stages the exact verified artifact and launches
it with a clean environment inside the native restricted sandbox. The signed
operation requires:

- `isolation_class=native_restricted`, T0 baseline and ceiling;
- `network.mode=none`, `dns_mode=none`, no protocols, zero connections, no
  public Internet, and no metadata access;
- credential classes exactly `none`;
- one fixed operation and no caller-controlled executable, arguments, working
  directory, environment, path, file, pipe, socket, or endpoint;
- read-only staged executable and inputs plus one private ephemeral working
  directory that is destroyed after execution;
- one child process, bounded open files, CPU, memory, wall time, output bytes,
  and ephemeral storage; and
- cooperative cancellation followed by bounded termination.

The helper receives one closed JSON object on stdin and emits one closed JSON
object on stdout. It reads to EOF before parsing, rejects input over 1 MiB,
limits stdout to 1 MiB and stderr to 64 KiB, and emits no progress stream.
Stderr is diagnostic-only, bounded, redacted, and never parsed into authority.
The process receives no secret, credential, bearer token, tenant credential,
ambient proxy, home directory, package cache, evidence path, or network handle.

## Closed input

The versioned helper input binds:

| Field group | Required values |
|---|---|
| Protocol | schema/contract version, request ID, operation, helper identity expectation |
| Query | UTF-8 KQL, canonical query digest, requested limit |
| Workspace | logical source/resource, workspace identity digest, qualification and capability digests |
| Schema | database name, exact tables and columns, scalar type/nullability, schema digest and expiry |
| Policy | validator profile/version, operator/function registry digest, maximum limit, complexity limits |
| Execution | deadline and cancellation token identity; no wall-clock authority supplied by the model |

The helper verifies duplicate-key-free closed JSON, canonical field ordering
where required, valid UTF-8, exact versions and digests, sorted unique tables and
columns, compatible scalar types, and all size/count limits. Raw ARM IDs,
credentials, endpoints, policy decisions, actor details, evidence content, and
audit records never cross this process boundary.

V1 admits at most 64 tables, 8,192 total columns, 65,536 query bytes, 8,192
syntax nodes, depth 64, 64 pipeline operators, 256 projected columns, 64
aggregates, 32 exact union operands, and a final row limit from 1 through 10,000.
The Go boundary may impose smaller values and the lower value always wins.

## Semantic environment

The helper constructs a new `GlobalState` for every request with one synthetic
cluster and one current database. That database contains only `TableSymbol` and
`ColumnSymbol` objects derived from the exact admitted CYB-97 schema. It contains
no stored functions, external tables, materialized views, entity groups,
alternate clusters/databases, open tables, wildcard symbols, or ambient service
metadata.

`KustoCode.ParseAndAnalyze(query, globals, cancellationToken)` is mandatory.
Parsing without analysis is never sufficient. Any parser, binder, semantic,
syntax-tree, skipped-token, missing-token, bad-node, unknown-symbol, open-symbol,
ambiguous-symbol, type, or cancellation diagnostic denies the request. The
validator walks every syntax node and uses `ReferencedSymbol` and related
semantic information; token or substring scanning is never proof of safety.

## V1 query profile

The root must be one `QueryBlock` containing exactly one
`ExpressionStatement`, no directives, no skipped tokens, and no trailing
semicolon. This deliberately excludes control/management commands, `set`,
`let`, query-parameter declarations, aliases, `restrict`, patterns, local or
stored function declarations, and multi-statement programs. Local scalar and
tabular `let` statements can be considered only in a reviewed contract revision
with recursive body validation and cycle/depth limits.

Every root table reference must resolve to an exact table in the supplied
schema. Qualified paths and entity expressions are denied. Exact-table `union`
is permitted only when every operand resolves directly to an admitted table,
contains no wildcard, and omits or explicitly disables `isfuzzy`; `best_effort`
cannot be set because all `set` statements are denied. Cross-cluster/database,
`cluster()`, `database()`, `external_table()`, `materialized_view()`,
`stored_query_result()`, and `entity_group()` are denied.

The initial query-operator allowlist is:

- `where`/`filter`;
- `project`, `project-away`, `project-keep`, `project-rename`, and `extend`;
- `summarize`, `count`, and `distinct`;
- `sort`/`order`, `top`, `take`, and `limit`;
- exact-table `union` under the restrictions above; and
- `parse` and `parse-where` with literal patterns and bounded output columns.

All other operators are denied, including `evaluate`, `externaldata`, `execute`,
`consume`, `getschema`, `invoke`, `macro-expand`, `materialize`, `partition`,
`fork`, `facet`, `join`, `lookup`, `mv-apply`, `mv-expand`, `range`, `print`,
`datatable`, `find`, `search`, `sample`, `sample-distinct`, `serialize`, `scan`,
`make-series`, and every unclassified or newly introduced operator. V1 denies
all `evaluate` plugins rather than attempting to classify a changing plugin
surface; a future safe-plugin allowlist requires a new registry version and
adversarial qualification.

Scalar functions are allowlisted by resolved built-in `FunctionSymbol`, exact
signature, argument count/type, deterministic return type, and registry digest.
The initial families are boolean/comparison, null checks, closed scalar
conversion, string case/length/search/slice, arithmetic, datetime component and
timespan arithmetic, IP parsing/comparison, conditional `iff`/`case`, and
`coalesce`. Aggregates are limited to `count`, `countif`, `dcount`, `dcountif`,
`sum`, `sumif`, `min`, `max`, `avg`, and `avgif`. Any user/stored function,
unknown overload, dynamic invocation, external effect, nondeterministic current
time, ingestion-time dependency, dynamic/object output, unbounded collection
builder, or unreviewed function is denied.

Dynamic columns are not admitted by CYB-97 v1, and a query cannot synthesize a
dynamic, property bag, array, open row, or unknown column. Every output column
must have a closed supported scalar type and a unique bounded name. Operator and
expression nesting, column fanout, aggregate count, sort keys, literal sizes,
regex/pattern sizes, and total syntax nodes are counted after binding.

## AST-derived terminal bound

The helper never appends text to the caller query. After successful analysis it:

1. clones the validated root expression;
2. parses a helper-owned constant template containing a terminal `take` with the
   admitted invariant-culture integer limit;
3. clones only the template's `PipeExpression` separator and `TakeOperator`;
4. constructs a new `PipeExpression(validatedClone, pipeToken, takeOperator)`;
5. formats that AST with `KustoFormatter` into canonical KQL; and
6. reparses and reanalyzes the formatted result against the same `GlobalState`.

Kusto.Language 12.4.1 exposes immutable syntax nodes but keeps the four-argument
`PipeExpression` constructor non-public. The pinned helper therefore resolves
that exact constructor by type signature and invokes it only with the three
cloned, already-typed nodes above and a null diagnostic list. Missing or changed
constructor shape, invocation failure, or a different post-bind tree is a hard
compatibility denial; there is no text-append fallback. This dependency on an
internal API is covered by the exact package pin, managed conformance test, and
version-migration gate.

The integer is the lower of request and policy maxima. It is typed numeric data,
not query text; no untrusted byte is concatenated into the template. An existing
user `take`, `limit`, or `top` may narrow results, but the helper always adds its
own final literal `take`, so upstream optimizer or query changes cannot remove
the admitted ceiling from the returned plan.

The second tree must contain the validated source expression followed by exactly
one new terminal `TakeOperator` whose constant value equals the admitted limit.
Its referenced tables, columns, functions, output schema, and all non-terminal
nodes must match the pre-rewrite semantic inventory. Any formatter, clone,
binding, inventory, diagnostic, or limit mismatch is an internal fail-closed
error. The response contains canonical KQL only after this proof, plus digests
of the original tree, semantic inventory, bounded tree, canonical KQL, schema,
registry, helper, package closure, and request.

## Go validator, audit, replay, and revocation

The public Go port accepts a typed `ValidateRequest`; it never accepts an
executable, argv, environment, path, generic JSON, or helper response as trusted
state. Before launch it verifies current actor/scope authority, CYB-97 capability
and schema freshness, policy decision, limits, helper manifest/signature,
artifact/package/runtime qualification, revocation state, deadline, E-stop, and
an audit reservation bound to the exact request digest.

After launch it strictly decodes the helper response, recomputes every digest,
and verifies schema, query, limit, semantic inventory, helper identity,
canonical output, and provenance bindings. It then commits the accepted or
denied audit event before returning a usable result. Required audit failure
withholds success. Audit contains only identities, digests, versions, limits,
outcome, stable reason codes, timing class, and redacted diagnostics—never KQL,
literals, table/column names, workspace IDs, executable paths, environment,
stderr, secrets, or vendor bodies.

The idempotency key binds the full canonical request. Exact concurrent requests
may coalesce only after current admission. An exact replay rechecks current
authority, helper signature, artifact digest, qualification, schema expiry,
policy, revocation, E-stop, and prior audit proof before returning the same
immutable result. Changed reuse conflicts. Revocation or expiry removes retained
results from use; no restart is required.

## Failure and recovery

| Condition | Result |
|---|---|
| Malformed/oversize input, unsupported KQL, semantic diagnostic | Stable denied result; helper identity and redacted reason retained |
| Authority, policy, signature, artifact, runtime, schema, or revocation failure | Denied before launch when observable; no accepted result |
| Deadline or caller cancellation | Typed timeout/cancelled; process terminated; no partial output adopted |
| Sandbox/resource/output limit | Typed exhausted/unavailable result; no accepted result |
| Crash, malformed/tampered response, digest or AST-proof mismatch | Fail-closed internal/unavailable; staged state destroyed |
| Required audit unavailable | No usable accepted result; exact retry may repair the same deterministic append |
| Lost response after durable accepted audit | Exact fresh-authority replay returns the same digest-bound result |
| Helper outage or unsupported RID | Validator unavailable; Sentinel query dispatch remains disabled |

Recovery always starts from a newly verified artifact and current authority.
It never trusts a temporary file, partial stdout, cached process, older helper,
stale schema, prior credential, or unsigned fallback. Rollback disables the
operation, revokes the manifest/policy revision and retained plans, restores the
last separately signed and qualified version only through ordinary admission,
and reruns the conformance corpus before re-enabling Sentinel validation.

## Compatibility and rollout

V1 is compatible only with the exact contract, registry, Kusto.Language,
runtime, RID, signed artifact, and CYB-97 schema versions recorded in the
qualification. A package, runtime, formatter, syntax kind, operator/function
registry, output schema, limit, or diagnostic behavior change requires a new
helper identity and full corpus qualification. Unknown additive upstream syntax
is denied rather than inherited.

Rollout starts disabled, publishes reproducible artifacts for each Tier 1 native
RID, admits the signed manifest, runs network-denial and deterministic fixture
suites, then performs a bounded credentialless validation canary before the
Sentinel execution leaf may consume plans. Compose uses the matching Linux
artifact; Windows remains Docker-only best effort. The DGX profile never grants
GPU access to the validator.

## Verification trajectory

Task 2 publishes the closed JSON schemas, canonical fixtures, denial registry,
compatibility matrix, and Go port. Tasks 3 and 4 build and qualify the helper,
semantic registry, and AST rewrite. Task 5 integrates native execution,
authority, audit, replay, revocation, and recovery. Task 6 supplies accepted and
adversarial corpora. Tasks 7 and 8 run managed-runtime, network-denial,
reproducibility, focused, race, architecture, supply-chain, and clean full CI
gates and publish checksummed evidence.

Primary authoritative references:

- [Parse and analyze queries with Kusto.Language](https://learn.microsoft.com/en-us/kusto/api/netfx/kusto-language-parse-queries?view=microsoft-fabric)
- [Kusto.Language overview](https://learn.microsoft.com/en-us/kusto/api/netfx/about-kusto-language?view=microsoft-fabric)
- [Microsoft.Azure.Kusto.Language 12.4.1](https://www.nuget.org/packages/Microsoft.Azure.Kusto.Language/12.4.1)
- [KQL statements](https://learn.microsoft.com/en-us/kusto/query/statements?view=microsoft-fabric)
- [`externaldata` operator](https://learn.microsoft.com/en-us/kusto/query/externaldata-operator?view=microsoft-fabric)
- [`evaluate` operator](https://learn.microsoft.com/en-us/kusto/query/evaluate-operator?view=microsoft-fabric)
- [`set` statement](https://learn.microsoft.com/en-us/kusto/query/set-statement?view=microsoft-fabric)
- [`union` operator](https://learn.microsoft.com/en-us/kusto/query/union-operator?view=microsoft-fabric)
- [`take` operator](https://learn.microsoft.com/en-us/kusto/query/take-operator?view=microsoft-fabric)
- [NuGet lock files and locked restore](https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files)
- [.NET single-file deployment](https://learn.microsoft.com/en-us/dotnet/core/deploying/single-file/overview)

Microsoft documentation and package metadata are informative inputs. The COH
PRD, trust-boundary ADR, signed tool contract, this frozen profile, and current
policy remain normative.
