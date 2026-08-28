# Signed pySigma helper design

| Field | Decision |
|---|---|
| Issue | CYB-105 / COH-E15-01 |
| Requirements | FR-055, FR-056, SEC-019 |
| Sigma specification | 2.1.0, basic rules only |
| Compiler core | pySigma 1.5.0 (`cb6ac5ab72957d6ca6529c5c15548672329436bb`) |
| Build/runtime | CPython 3.13.15; PyInstaller 6.22.2 |
| Native RIDs | `osx-arm64`, `linux-x64`, `linux-arm64` |
| Tool operation | `sigma.compile` |
| Action tier | T0, credentialless, read-only, `network:none` |
| Security decision | Exact explicitly imported backends inside the existing signed native-executor boundary; compiled text is untrusted until native validation |

## Purpose and authority

The helper compiles one bounded Sigma basic rule through one exact backend and
one explicit tenant mapping. It returns a typed compilation result or a complete
typed denial. It never publishes a detection, contacts a target, discovers a
plugin, chooses a mapping, ignores an unsupported construct, or grants support.

The helper is a parser and compiler, not an authority. The Go boundary owns
actor, organization, tenant, case, source, target, capability, mapping,
qualification, policy, deadline, audit, replay, revocation, and provenance
checks. A compiled result has state `compiled_untrusted`. Only COH-E15-02 may
advance it after rebinding it to current discovered schema and successful
validation by the corresponding COH native parser. Publication remains a later
reviewed lifecycle operation.

## Audited upstream surface

The design was frozen against the exact release commits shown below. A tag,
wheel version, or compatible dependency range is not sufficient for admission.

| COH target | Package and exact release commit | Explicit class and format | V1 disposition |
|---|---|---|---|
| Elastic | `pySigma-backend-elasticsearch` 2.1.0, `5bf3529d1450e46b6a937ad29ecf0e122fbadf9d` | `ESQLBackend`, `default` | Qualified candidate; output language `esql` |
| Splunk | `pySigma-backend-splunk` 2.1.0, `68a5e382f1d57a14337c6e66022af34da1e3bfe6` | `SplunkBackend`, `default` | Qualified candidate; output language `spl` |
| Sentinel | `pySigma-backend-kusto` 1.0.1, `c83f737a39f1084f30022150482f8dbbc035034b` | `KustoBackend`, `default` | Qualified candidate; output language `kql` |
| Security Onion | `pySigma-backend-opensearch` 2.0.3, `42c52c8d6f3a717485091f9860a795844194c0a8` | none | Recorded but unavailable in v1 |

`Qualified candidate` means eligible for the helper conformance corpus. It does
not mean a target release is supported. Exact wheel hashes, dependency closure,
bundle digest, runtime digest, mapping revision, target version, schema, native
validator, and conformance evidence must all qualify before use.

Security Onion is deliberately unavailable because its COH connector accepts a
closed typed OQL JSON document, whereas the audited OpenSearch backend emits
Lucene text, monitor objects, or PPL. Treating those representations as OQL
would be a semantic guess and violate FR-056. A later reviewed adapter may lower
the bounded Sigma intermediate form directly to the COH OQL contract. There is
no Lucene, PPL, generic OpenSearch, or hidden fallback path.

Elastic Lucene, DSL-with-embedded-Lucene, EQL, Kibana NDJSON, SIEM-rule JSON,
Splunk `savedsearches`, SPL2, Kusto Microsoft XDR, Sentinel ASIM, and Azure
Monitor's bundled inferred mappings are not v1 helper operations. Publication
formats can contain mutable object settings and are outside this compiler.

## Closed Sigma v1 profile

The helper accepts exactly one UTF-8 YAML document containing exactly one Sigma
basic rule. Correlation rules, filters, collection actions (`global`, `reset`,
and `repeat`), multiple documents, references to other rules, and rule-loading
from paths are denied. The rule must use Sigma specification 2.1.0 semantics and
contain only the following top-level fields:

- required: `title`, `id`, `status`, `logsource`, and `detection`;
- optional metadata: `name`, `description`, `author`, `date`, `modified`,
  `references`, `tags`, `falsepositives`, and `level`.

Unknown top-level keys, `custom` data, backend hints, output directives, and
arbitrary taxonomy extensions are denied. Metadata is bounded and preserved by
digest but is not interpolated into native query text.

`logsource` contains only bounded `category`, `product`, `service`, and
`definition` strings. It is identity input to the explicit mapping; it never
selects an ambient pipeline or inferred target resource.

`detection` admits named selections composed of closed mappings and lists plus
one condition expression. V1 admits equality, boolean composition, bounded
lists, and these modifiers:

- `contains`, `startswith`, `endswith`, `all`, `exists`;
- `cidr`; and
- `lt`, `lte`, `gt`, `gte`, and `neq` for typed scalar comparisons.

Unbound keyword searches, regular expressions and flags, `expand`, `fieldref`,
`base64`, `base64offset`, `wide`, UTF-16 modifiers, `windash`, timestamp
modifiers, unreviewed modifiers, and newly introduced syntax are denied. This
profile may initially deny a modifier on an individual backend if the exact
backend does not implement equivalent semantics. No transformation may drop a
detection item or turn an unsupported value into a wildcard.

Conditions may use selection identifiers, parentheses, `and`, `or`, `not`, and
bounded `1/all of <explicit-prefix>*` forms. `them`, arbitrary glob patterns,
large threshold expansions, correlation expressions, and conditions producing
zero or multiple native queries are denied. One admitted rule must produce
exactly one non-empty native query.

## YAML preflight and complexity bounds

pySigma 1.5.0 calls `yaml.safe_load_all`, which prevents Python object
construction but does not by itself bound aliases, nesting, document count, or
expanded object size. COH therefore performs a token/event preflight before
constructing a pySigma rule and never exposes `SigmaCollection.load_ruleset`.

V1 limits are:

| Resource | Hard maximum |
|---|---:|
| Transport document | 1 MiB |
| Sigma YAML | 128 KiB |
| YAML documents / Sigma rules | 1 / 1 |
| YAML aliases / anchors / tags | 0 / 0 / standard scalar tags only |
| YAML nodes / depth | 4,096 / 32 |
| Mapping entries / sequence entries | 2,048 / 2,048 |
| Scalar bytes / scalar count | 16 KiB / 4,096 |
| Detection selections / items / values | 64 / 512 / 2,048 |
| Fields / distinct mapped fields | 256 / 256 |
| Condition tokens / nesting / expanded terms | 512 / 32 / 2,048 |
| Metadata references / tags / false positives | 32 / 64 / 32 |
| Native queries / native output bytes | 1 / 256 KiB |
| Diagnostics / reason codes | 32 / 32 |

Duplicate mapping keys, merge keys, explicit or implicit non-scalar keys,
non-finite numbers, timestamps parsed as ambient objects, binary values, NUL,
invalid UTF-8, non-canonical UUIDs/dates, and trailing content deny. YAML input
is converted to a closed primitive tree and validated again before pySigma sees
it. The helper recomputes counts after pySigma parsing and after processing so a
library change cannot bypass the preflight.

The Go policy may impose lower limits. The lower value always wins. Process
limits are 15 seconds wall time, 10 seconds CPU, 512 MiB memory, 1 MiB combined
output, 16 MiB ephemeral storage, one process, and 64 open files. Qualification
must demonstrate lower stable operating bounds before production enablement.

## Explicit mappings and pipeline construction

The caller supplies a closed typed mapping projection already admitted by Go.
It binds target, native language, exact resource/table/index, mapping ID and
revision, source and target schema digests, logsource match, and a sorted unique
one-to-one field map. Mapping values are identifiers, not templates or query
fragments. One-to-many, many-to-one, wildcard, dynamic, ambiguous, absent, or
type-incompatible mappings return `needs_mapping`.

The helper constructs a fresh `ProcessingPipeline` in Python code for every
request from only helper-owned processing item classes. It uses exact field
mapping transformations followed by `StrictFieldMappingFailure`. It may set the
one exact resource/table/index through a helper-owned constant transformation.
It does not accept processing-pipeline YAML, pipeline names, priorities,
templates, postprocessors, finalizers, backend options, callbacks, output
settings, or caller-controlled classes.

The following pySigma facilities are unreachable by construction:

- `InstalledSigmaPlugins.autodiscover`, plugin directory downloads, entry-point
  enumeration, and `sigma-cli`;
- `ProcessingPipelineResolver` file resolution and arbitrary
  `ProcessingPipeline.from_yaml`;
- template `vars` Python imports and Jinja postprocessing/finalization;
- file, HTTP, and command placeholder transformations;
- MITRE ATT&CK or D3FEND network/cache loaders;
- arbitrary backend keyword arguments, output paths, and publication formats;
- `collect_errors=True`, callbacks that can suppress results, or any
  skip-unsupported behavior.

Backends are imported by exact module and class. The helper constructs them
with `collect_errors=False`, an exact helper-owned pipeline, no caller options,
and the single allowlisted output format. Any exception, collected parser
error, processing failure, missing mapping, empty result, extra result, lossy
transformation, or unexpected type denies the entire request.

## Deterministic protocol

The existing `nativeexecutor` stages and verifies the exact signed executable,
launches it with an empty environment, denies network and DNS, bounds resources,
and supplies one private ephemeral working directory. The helper accepts one
closed duplicate-key-free JSON object on stdin and emits one closed JSON object
on stdout. No argument, path, environment variable, package cache, home
directory, proxy, credential, socket, or endpoint is caller controlled.

The request binds:

| Group | Required binding |
|---|---|
| Protocol | schema and contract version, UUIDv7 request ID, `sigma.compile` |
| Source | Sigma YAML, source digest, Sigma profile/version |
| Target | target enum, native language, backend class/version/commit, output format |
| Mapping | mapping ID/revision, exact resource, sorted field/type bindings, mapping and schema digests |
| Admission | capability, qualification, policy, and audit-reservation digests |
| Helper | expected RID, artifact, package closure, runtime, backend-matrix, and profile digests |
| Execution | canonical deadline and lower policy limits |

The response contains outcome (`compiled_untrusted`, `needs_mapping`,
`unsupported`, or `denied`), sorted stable reason codes, normalized diagnostics,
zero or one native query, language and target, source/mapping/schema/backend
bindings, rule and query digests, helper identity, provenance digest, and
response digest. It contains no traceback, source path, environment, package
path, raw exception, credential, endpoint, tenant/resource identifier, or
unbounded vendor text.

Canonical hashes use COH-CJ-1 domain-separated JSON. Ordering is explicit for
all sets and maps; locale is `C`, timezone is UTC, hash seed is fixed, and the
helper does not consult wall clock, randomness, filesystem enumeration, network,
or ambient process state while compiling. A repeated exact request must return
the same semantic response digest. Request IDs and deadlines are bindings but
are excluded from the semantic compilation digest.

## Supply chain and packaging

The runtime pins CPython 3.13.15 because all audited packages require Python
3.10 or later and the selected release avoids making a new interpreter line
part of the first qualification. The build pins PyInstaller 6.22.2 and every
wheel, sdist, bootloader, compiler, SDK, libc deployment baseline, and transitive
dependency by SHA-256. Networked resolution occurs only in a controlled build
input-fetch stage. Restore and both reproducibility builds run from the offline
wheelhouse with dependency resolution disabled.

The exact closure includes pySigma, the three candidate backend packages,
PyYAML, Jinja2, Requests, jq bindings, packaging, pyparsing, typing extensions,
PyInstaller and its hooks/bootloader dependencies, plus all transitives used by
the closed import graph. `diskcache` and its stubs are deliberately excluded
from the runtime lock: pySigma declares them for optional remote MITRE data
modules, which this helper never imports or exposes. The build TOC fails if a
MITRE data or `diskcache` module enters the artifact. Packages merely present on
the build host are not importable. The build fails on an extra, missing,
floating, prerelease, yanked, incompatible, unhashed, unlicensed, or vulnerable
runtime input.

Each RID is built natively as a self-contained executable with closed helper
import roots. The exact Elastic package initializer eagerly imports its Lucene,
EQL, and Elastalert siblings, so those dependency-closure modules may be
present but have no selectable protocol value, constructor, option, or output
format. Build analysis proves that the three allowlisted backend classes are
present and that plugin discovery and pipeline resolution modules are absent.
Two clean builds with normalized source date, paths, locale, and toolchain must
produce the same executable digest. If PyInstaller cannot meet
that reproducibility gate on a RID, that RID remains unavailable; switching
packagers requires a design revision.

Release evidence records source commits, source and wheel hashes, Python and
packager inputs, compiler/SDK identity, complete CycloneDX SBOM, license report,
vulnerability snapshot, artifact digest, reproducibility result, and
SLSA-compatible provenance. Admission then requires a COH Ed25519-signed tool
manifest for that exact artifact. Upstream Git/Sigstore/package signatures are
build-input checks and never replace COH publisher authority.

## Go boundary, audit, replay, and revocation

The public Go service accepts a typed compile request; it never accepts an
executable, argv, environment, path, generic JSON, backend option, or helper
response as trusted state. Before launch it verifies current actor/scope,
capability, mapping and schema freshness, policy, helper manifest/signature,
artifact/runtime/backend qualification, revocation, deadline, E-stop, and an
audit reservation bound to the full canonical request.

After launch it strictly decodes the response, recomputes all digests, verifies
the exact request/helper/backend/mapping bindings, validates output language and
size, and rejects any accepted result containing diagnostics or extra output.
It commits the outcome audit before returning a result. Required audit failure
withholds the result. Native query text, literals, rule content, field names,
tenant/resource IDs, stderr, paths, and credentials never enter audit records.

An idempotency key binds the full request. Exact concurrent requests may
coalesce only after current admission. Replay rechecks authority, signature,
artifact, qualification, mapping/schema freshness, policy, revocation, E-stop,
and prior audit proof. Changed reuse conflicts. Revocation or expiry prevents
retained results from progressing to native validation without restart.

The native adapter re-verifies the signed manifest and qualified runtime
attestation before every invocation. Its trust port must resolve current
production publisher and qualification authority; deterministic keys used by
tests are fixtures only and cannot authorize a release. The broker-owned runner
must echo the manifest, artifact, operation, action tier, exact backend, mapping
identifier, and mapping revision. Any drift, stderr, truncation, oversized
output, malformed response, timeout, or cancellation withholds the result and
returns only a typed error. A later independent request may recover after a
cancellation; the adapter retains no guessed completion state.

## Native-validation handoff

Every `compiled_untrusted` result carries the exact native language and the
mapping/schema/resource digests it was compiled against. COH-E15-02 must create
a new typed native-validation request and invoke exactly one matching validator:

| Helper output | Required next validator | Additional rule |
|---|---|---|
| `esql` | `internal/connector/elasticesql` | Exact discovered index and field schema; no wildcard index |
| `spl` | `internal/connector/splunkparser` plus Splunk parser preflight | Connector adds absolute time and result bounds; no macro/lookup/custom command |
| `kql` | signed `internal/connector/kustovalidator` helper | Exact qualified workspace schema and final AST-derived `take` |

The native validator must parse the generated query, bind every resource and
field to current discovered schema, impose execution bounds, and return its own
provenance. A mismatch returns `needs_mapping`, `unsupported`, or `denied`; it
never causes recompilation with a broader pipeline. No result is labeled
`supported`, tested, approved, publishable, or executable at CYB-105.

## Failure and recovery

| Condition | Result |
|---|---|
| Malformed/duplicate/oversize YAML or JSON | `denied` with stable structural reason |
| Missing, ambiguous, stale, or incompatible mapping | `needs_mapping`; no native query |
| Unsupported Sigma construct, backend, output, or target | `unsupported`; no native query |
| pySigma/backend parse or conversion error | Whole request denied; never partial |
| Authority, policy, signature, artifact, runtime, qualification, or revocation failure | Denied before launch when observable |
| Deadline or caller cancellation | Typed timeout/cancelled; process group terminated; no output adopted |
| Sandbox memory/CPU/storage/process/output limit | Typed exhausted/unavailable; no output adopted |
| Crash, stderr, malformed/tampered response, digest mismatch, or nondeterminism | Fail-closed internal/unavailable |
| Required audit unavailable | No usable result; exact retry may repair the audit append |
| Unsupported RID or helper outage | Detection compilation remains unavailable |

Recovery always starts a fresh process from a newly verified artifact and
current authority. No daemon, module cache, temporary file, partial stdout,
prior mapping, old result, or unsigned fallback is reused. Rollback disables
the operation, revokes the affected manifest/profile/backend matrix and
retained results, and restores a prior version only through ordinary signed
admission and full conformance qualification.

## Compatibility and rollout

V1 compatibility is exact across contract, Sigma profile/specification,
pySigma, every backend, Python, packager, RID, artifact, package closure,
mapping schema, backend matrix, diagnostic taxonomy, and native handoff. Any
change creates a new helper identity and requires the full success, denial,
mapping, malicious-input, native-handoff, replay, cancellation, crash,
reproducibility, and cross-platform corpus. Unknown additive upstream behavior
is denied rather than inherited.

Rollout starts disabled. Each target/backend/RID is enabled independently only
after its exact capability snapshot and evidence qualify. Security Onion stays
explicitly unavailable. A backend qualification may be revoked without
disabling unrelated qualified backends, but there is no automatic downgrade or
version range.

## Primary upstream references

- [pySigma 1.5.0 release](https://github.com/SigmaHQ/pySigma/releases/tag/v1.5.0)
- [pySigma backend interface](https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html)
- [pySigma processing pipelines](https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html)
- [Sigma specification 2.1.0](https://github.com/SigmaHQ/sigma-specification/tree/v2.1.0)
- [Elasticsearch backend 2.1.0](https://github.com/SigmaHQ/pySigma-backend-elasticsearch/releases/tag/v2.1.0)
- [Splunk backend 2.1.0](https://github.com/SigmaHQ/pySigma-backend-splunk/releases/tag/v2.1.0)
- [OpenSearch backend 2.0.3](https://github.com/SigmaHQ/pySigma-backend-opensearch/releases/tag/v2.0.3)
- [Kusto backend 1.0.1](https://github.com/AttackIQ/pySigma-backend-kusto/releases/tag/v1.0.1)
- [CPython 3.13.15](https://www.python.org/downloads/release/python-31315/)
- [PyInstaller 6.22.2](https://pyinstaller.org/en/v6.22.2/)
