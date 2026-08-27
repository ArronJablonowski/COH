# Splunk parser policy contract v1

This contract publishes COH's default-deny SPL profile for CYB-99 / COH-E14-02
and FR-046, FR-051. The local structural compiler is authoritative. Splunk's
v2 parser is called only on a locally accepted canonical candidate with
`parse_only=true`, `enable_lookups=false`, and `reload_macros=false`.

The exact allowed command set is `fields`, `head`, `search`, `sort`, `stats`,
and `table`. Backticks, macros, lookups, custom commands, alternate generating
commands, saved state, dynamic execution, external effects, and every
unclassified command fail closed at every subsearch depth.

Public policy/audit evidence contains identities, outcomes, reason codes, and
digests only. Native SPL, literals, parser bodies, credentials, and SIDs are
never audit metadata. See `docs/design/splunk-parser-policy.md` for grammar,
limits, threat model, compatibility, recovery, and migration decisions.

Every internal plan carries the exact UTC half-open `earliest`/`latest` range
and a self-verifying plan digest. Time is submitted through the future typed
job request and is never accepted from inline SPL.
