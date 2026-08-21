#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
product="$root/docs/design/product-contract.md"
platform="$root/docs/design/platform-support-matrix.md"
adr="$root/docs/adr/0001-trust-boundaries.md"
adr_verify="$root/docs/adr/0001-trust-boundaries-verification.md"
tiers="$root/docs/security/action-tier-decision-table.md"
prd="$root/outputs/COH-PRD.md"

for command in awk rg; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'error: required command is unavailable: %s\n' "$command" >&2
    exit 2
  }
done

for path in "$product" "$platform" "$adr" "$adr_verify" "$tiers" "$prd"; do
  [[ -f "$path" ]] || {
    printf 'error: required decision record is missing: %s\n' "$path" >&2
    exit 2
  }
done

require_literal() {
  local file=$1
  local value=$2
  rg -Fq "$value" "$file" || {
    printf 'FAIL missing literal in %s: %s\n' "$file" "$value" >&2
    return 1
  }
}

require_regex() {
  local file=$1
  local pattern=$2
  rg -q "$pattern" "$file" || {
    printf 'FAIL missing pattern in %s: %s\n' "$file" "$pattern" >&2
    return 1
  }
}

for file in "$product" "$adr" "$tiers"; do
  require_literal "$file" '| Status | Ready for approval |'
done
require_literal "$adr_verify" '| Status | Ready for approval with ADR-0001 |'
require_literal "$platform" '| Status | Draft — dependency and human review pending |'
require_literal "$platform" '| Approval status | Blocked by approval of COH-E01-01, COH-E01-02, and COH-E01-03 |'

require_regex "$product" '^## Personas and authority$'
require_regex "$product" '^## Supported v1 workflows$'
require_regex "$product" '^## Measurable success outcomes$'
require_regex "$product" '^## Explicit non-goals$'
require_regex "$product" '^## Request and failure behavior$'
require_regex "$product" '^## Requirement traceability$'

workflow_count=$(awk '
  /^## Supported v1 workflows$/ { inside=1; next }
  inside && /^## / { inside=0 }
  inside && /^[0-9]+\. / { count++ }
  END { print count+0 }
' "$product")
[[ "$workflow_count" == 10 ]] || {
  printf 'FAIL expected 10 supported workflows, found %s\n' "$workflow_count" >&2
  exit 1
}

for profile in \
  'Native macOS workstation' 'Native Linux server' 'Native DGX' \
  'Compose on macOS' 'Compose on Linux' 'Windows host'; do
  require_regex "$platform" "^\\| ${profile} \\|"
done
for connectivity in Connected 'Restricted connected' 'Air-gapped'; do
  require_regex "$platform" "^\\| ${connectivity} \\|"
done
require_literal "$platform" 'Docker absence must not alter native APIs'
require_literal "$platform" 'Windows is best-effort Docker-only'
require_regex "$platform" '(?i)Missing, stale, mismatched, or$'
require_regex "$platform" '^incomplete qualification evidence leaves a profile experimental or unsupported[.]$'
require_regex "$platform" '(?i)unknown OS, architecture, runtime, or profile.*reject'
require_regex "$platform" '(?i)24-hour test must observe zero DNS'
require_literal "$platform" 'shared Docker Desktop is not a T4 boundary'

for boundary in Identity Process Model Data Credential Broker Connector Validator Runner Audit 'T4 isolation'; do
  require_regex "$adr" "^\\| ${boundary} \\|"
done
require_regex "$adr" '^### 1\. The model is an untrusted planner$'
require_regex "$adr" '^### 2\. `coh-brokerd` is the sole action authority$'
require_regex "$adr" '^### 3\. Architecture and trust-boundary map$'
require_literal "$adr" 'External security-system boundary — untrusted remote state'
require_literal "$adr" 'Remote SIEM, CTI, vulnerability, and response APIs'
require_regex "$adr" '^## Failure semantics$'
require_regex "$adr" '^## Alternatives rejected$'
require_regex "$adr" '^## Non-goals$'
require_regex "$adr" '^## Change control$'
require_regex "$adr_verify" '^## Enforceable implementation rules$'
require_regex "$adr_verify" '^## Required verification matrix$'
require_regex "$adr_verify" '^## Completion evidence$'
require_literal "$adr_verify" 'public capability-surface'
require_literal "$adr_verify" 'exported-API capability'
require_regex "$adr_verify" '(?i)agent, provider, workflow'
require_regex "$adr_verify" '(?i)bypass the broker to obtain or reach'

if ! awk '
  /^```mermaid[[:space:]]*$/ { if (open) exit 1; open=1; count++; next }
  /^```[[:space:]]*$/ && open { open=0 }
  END { if (open || count != 1) exit 1 }
' "$adr"; then
  printf 'FAIL ADR must contain exactly one balanced Mermaid block\n' >&2
  exit 1
fi

for tier in T0 T1 T2 T3 T4; do
  count=$(rg -c "^\\| \\*\\*${tier} —" "$tiers" || true)
  [[ "$count" == 1 ]] || {
    printf 'FAIL expected one normative %s row, found %s\n' "$tier" "$count" >&2
    exit 1
  }
done

for heading in \
  '## Decision' \
  '## Normative T0–T4 decision table' \
  '## Approval binding and separation of duties' \
  '## Failure, cancellation, and recovery decision table' \
  '## Alternatives considered' \
  '## Non-goals' \
  '## Change control' \
  '## Requirement traceability'; do
  require_literal "$tiers" "$heading"
done

for concept in authorization approvals isolation evidence rollback retry uncertain cancellation recovery E-stop; do
  require_regex "$tiers" "(?i)${concept}"
done
require_regex "$tiers" '(?i)unknown or ambiguous.*denied'
require_regex "$tiers" '(?i)two distinct eligible.*human approvers'
require_regex "$tiers" '(?i)neither.*requestor'

if rg -n -i \
  'until (a )?second eligible human|until the second person|until a second authenticated human approver' \
  "$product" "$adr" "$adr_verify" "$tiers" "$prd"; then
  printf 'FAIL ambiguous T4 staffing language remains\n' >&2
  exit 1
fi

if rg -n '\b(TODO|TBD|FIXME)\b' "$product" "$platform" "$adr" "$adr_verify" "$tiers"; then
  printf 'FAIL unresolved placeholder found in decision record\n' >&2
  exit 1
fi

printf 'design-decision summary: workflows=%s platforms=6 connectivity=3 boundaries=11 tiers=5 mermaid=1 ambiguity=0 failures=0\n' \
  "$workflow_count"
