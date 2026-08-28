# COH-E14-02 Splunk parser policy design

| Field | Decision |
|---|---|
| Issue | CYB-99 / COH-E14-02 |
| Requirements | FR-046, FR-051 |
| Supported deployment | Qualified self-managed Splunk Enterprise 9.4 and 10.0 search heads |
| Caller language | `spl`, restricted COH profile using logical resource and field names |
| Security decision | Local structural compiler is authoritative; Splunk v2 parser is a non-authorizing conformance oracle |
| Mutability | Read-only, historical searches only |

## Authoritative vendor behavior

Splunk documents `POST /services/search/v2/parser` as the supported semantic
parser; the v1 parser is deprecated and disabled from 9.0.1 onward. COH calls
v2 with exactly `output_mode=json`, `parse_only=true`,
`enable_lookups=false`, and `reload_macros=false`. `parse_only=true` prevents
evaluation of subsearches and expansion through time terms, lookups, tags,
event types, and sourcetype aliases. The parser never creates a search job.

Splunk encloses subsearches in square brackets, evaluates nested subsearches
inside-out, and otherwise permits a vendor default nesting depth of eight. Time
bounds written in one search or subsearch do not constrain another. COH
therefore prohibits inline time modifiers, applies the admitted UTC half-open
range through the later typed job request, and uses substantially smaller local
recursion and count limits.

Search macros use backticks and can expand to arbitrary fragments or generating
commands. COH rejects every backtick byte before string decoding; setting
`reload_macros=false` is defense in depth, not the macro control.

Splunk's current risky-command list includes `collect`, `delete`, `dump`,
`map`, `mcollect`, `meventcollect`, `outputcsv`, `outputlookup`, `run`,
`runshellscript`, `script`, `sendalert`, `sendemail`, and `tscollect`.
Splunk warns on these commands but can still run them after acceptance or when
safeguards are disabled. COH treats all of them as unconditional denials. It
also explicitly denies the issue-required `rest`, `savedsearch`, `loadjob`,
all lookup commands, and every unclassified or custom command.

Primary references:

- <https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.2/search-endpoints/search-endpoint-descriptions>
- <https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.2/subsearches/about-subsearches>
- <https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.0/best-practices-for-splunk-platform-security/spl-safeguards-for-risky-commands>
- <https://help.splunk.com/en/splunk-cloud-platform/manage-knowledge-objects/knowledge-management-manual/10.4.2604/search-macros/use-search-macros-in-searches>
- <https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/quick-reference/command-quick-reference>

## Two independent gates

1. The local compiler tokenizes and parses the caller's restricted COH SPL
   profile, recursively traverses every bracketed subsearch, resolves only
   admitted logical resources and schema fields, applies mandatory scope and
   bounds, and emits a canonical immutable plan. Unknown syntax is denial.
2. The typed transport submits only that canonical plan to the v2 parser with
   expansion disabled. The response must be bounded, strict JSON and report the
   exact expected allowlisted command structure. Parser errors, extra commands,
   semantic drift, malformed output, timeout, or outage cannot produce an
   accepted validation.

The vendor response is never an authorization source. It cannot widen a local
plan, replace its resources, introduce a field, or turn a local denial into an
acceptance. No generic parser request or arbitrary namespace/app is exposed.

## Caller grammar and canonical plan

The caller profile is case-insensitive for keywords but case-sensitive for
logical identifiers. An explicit `search` is mandatory at the start of the
outer search and each subsearch. Bare terms, implicit generating commands,
comments, directives, wildcards, dollar substitutions, single-quoted strings,
backticks, semicolons, control characters, and vendor index/field names are not
part of v1.

The v1 command registry contains only six commands:

| Command | Typed behavior |
|---|---|
| `search` | One exact logical `resource=<id>` plus typed logical-field predicates and optional safe subsearch predicates |
| `fields` / `table` | Explicit unique projectable logical fields; mutually exclusive aliases for one projection node |
| `stats` | Bounded `count`, `dc`, `sum`, `avg`, `min`, or `max`, each with an explicit safe alias, optionally grouped by admitted fields |
| `sort` | At most eight admitted projected/group/aggregate fields with explicit ascending or descending direction |
| `head` | Positive row ceiling no larger than the admitted maximum |

Pipeline order is fixed. A non-aggregate pipeline is `search`, optional
projection, optional `sort`, optional `head`. An aggregate pipeline is
`search`, `stats`, optional `sort`, optional `head`. Repetition, reordering,
post-limit work, and multiple projection commands are denied.

Predicates support parentheses, `AND`, `OR`, unary `NOT`, and typed comparisons
`=`, `!=`, `<`, `<=`, `>`, and `>=`. Operators must be valid for the declared
field type. Literals are canonical strings, base-10 integers, booleans, UTC
timestamps, or validated IP addresses; the compiler performs deterministic
escaping when it renders native SPL. There is no caller-controlled raw fragment.

Each subsearch is a complete recursively validated pipeline under the same
source, authority, resource allowlist, schema, time range, and hard limits. It
must explicitly project exactly one admitted field and end with a positive
`head` no larger than 100. A subsearch cannot select an additional resource or
introduce a time modifier. Nested output is a predicate only; commands such as
`append`, `join`, `union`, `multisearch`, `map`, and `foreach` remain denied.

The compiler maps logical resource IDs to configured Splunk indexes and logical
schema names to configured vendor fields only after validation. It injects
mandatory tenant/source predicates when the deployment definition provides
those fields. It does not place inline earliest/latest terms in native SPL; the
future typed job request owns the admitted UTC bounds.

## Default-deny command policy

The exact allowlist above is complete. Any word in command position that is not
in it is `spl_command_unclassified`, including commands supplied by apps or
`commands.conf`. The following names receive stable specific denial reasons:

- mutation or external effect: `collect`, `delete`, `dump`, `mcollect`,
  `meventcollect`, `outputcsv`, `outputlookup`, `run`, `runshellscript`,
  `script`, `sendalert`, `sendemail`, `tscollect`;
- dynamic or indirect execution: `map`, `rest`, `savedsearch`, `loadjob`,
  `inputlookup`, `lookup`, `appendlookup`, macros/backticks, and custom commands;
- alternate data or control surfaces: `from`, `tstats`, `datamodel`, `pivot`,
  `metadata`, `metasearch`, `inputcsv`, `makeresults`, `union`, `multisearch`,
  `append`, `appendcols`, `appendpipe`, `join`, `foreach`, `localop`, and every
  optimizer/directive syntax not represented by the typed grammar.

Denial is recursive: the same registry and resource/schema rules apply at every
subsearch depth and within every parenthesized expression. Text scanning alone
is never used to prove safety.

## Hard limits

| Bound | V1 maximum |
|---|---:|
| UTF-8 input bytes | 65,536 |
| Tokens | 4,096 |
| Pipeline commands per search | 8 |
| Subsearch nesting depth | 2 |
| Total subsearches | 4 |
| Predicate nesting depth | 16 |
| Predicate nodes | 256 |
| Projection fields | 256 |
| Aggregations | 16 |
| Group fields | 16 |
| Sort fields | 8 |
| Subsearch output rows | 100 |

The tokenizer and recursive parser check cancellation at bounded intervals.
Overflow, invalid UTF-8, unmatched quotes/brackets/parentheses, duplicate fields
or aliases, unsupported literal types, trailing tokens, and depth/count excess
produce stable denial codes without echoing native text.

## Identity, policy, audit, replay, and revocation

An accepted plan digest binds the canonical query digest, source and resource
scope, actor and authority digests, capability digest, complete schema digest,
UTC range, admitted limits, validator/registry version, canonical AST, rendered
native SPL digest, and vendor-parser receipt. The common validation result
contains only its accepted/denied outcome, reason codes, validator version,
canonical query digest, and provenance digest.

The compiler retains accepted plans behind their query and plan digests for the
later execution leaf. Replay of identical input is deterministic. Any changed
query, schema, scope, actor, policy/audit digest, registry version, parser
receipt, or plan is a conflict. Expired capability/schema authority, revocation,
or an E-stop is rejected by the query broker before execution; an accepted
validation never grants fresh authority. Native text, literals, parser bodies,
credentials, and future SIDs are absent from audit metadata and public evidence.

If vendor preflight is unavailable after a local acceptance candidate, the
operation returns unavailable and stores no accepted plan. Cancellation or
timeout returns the matching common error. A subsequent fresh-authority retry
recompiles from canonical input; it does not reuse an uncertain vendor result.

The adapter retains discovered schema only for the exact capability digest and
expiry that produced it. Validation derives a resource-specific parser
definition from that qualified administrator allowlist, compiles locally, and
then posts the canonical candidate only to `/services/search/v2/parser`. The
returned command multiset must exactly match the locally emitted search,
projection/aggregation, sort, and head commands. The final plan digest binds
the common scope digest and the authenticated parser receipt. Query-ID
substitution, stale capability/schema, semantic drift, and applied policy
revocation remove or prevent retained plans before execution.

## Test and release trajectory

Task 2 publishes the strict plan, decision, registry, denial, and redacted-audit
contracts. Tasks 3 through 5 implement tokenizer, recursive parser, typed AST,
canonical compiler, and command policy. Task 6 adds the typed v2-parser call and
common `Validate` integration. Task 7 records sanitized 9.4/10.0 parser fixtures
and exercises mutations, nesting, ambiguity, cancellation, replay, revocation,
and recovery. Task 8 publishes conformance evidence and runs the clean baseline.

CYB-96 may consume only a validated plan produced by this boundary. Adding a
command, function, operator, implicit source, macro/lookup mode, parser endpoint,
or higher recursion/output bound requires a reviewed contract revision and new
adversarial evidence.
