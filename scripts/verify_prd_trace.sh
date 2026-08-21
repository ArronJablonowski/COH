#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
prd="$root/outputs/COH-PRD.md"
backlog="$root/outputs/COH-Linear-Backlog.md"
product_contract="$root/docs/design/product-contract.md"
trust_adr="$root/docs/adr/0001-trust-boundaries.md"
trust_verification="$root/docs/adr/0001-trust-boundaries-verification.md"
action_tiers="$root/docs/security/action-tier-decision-table.md"

for command in rg sort diff mktemp sed wc tr; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'error: required command is unavailable: %s\n' "$command" >&2
    exit 2
  }
done

for path in "$prd" "$backlog" "$product_contract" "$trust_adr" "$trust_verification" "$action_tiers"; do
  [[ -f "$path" ]] || {
    printf 'error: required input is missing: %s\n' "$path" >&2
    exit 2
  }
done

tmp=$(mktemp -d "${TMPDIR:-/tmp}/coh-prd-trace.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_heading() {
  local path=$1
  local heading_pattern=$2
  local description=$3
  local prefix='^#{2,4}[[:space:]]+([0-9]+([.][0-9]+)*[.)]?[[:space:]]+)?'

  rg -qi "${prefix}${heading_pattern}[[:space:]]*$" "$path" ||
    fail "$description is missing from ${path#$root/}"
}

assert_leaf_mapping() {
  local key=$1
  shift
  local line
  local requirements
  local actual="$tmp/${key}.backlog.actual"
  local expected

  expected="$tmp/${key}.backlog.expected"
  printf '%s\n' "$@" | LC_ALL=C sort -u > "$expected"
  line=$(rg -m 1 "^- \\[[ x]\\] \\*\\*${key} —" "$backlog") ||
    fail "$key is missing from the tracked Linear backlog mirror"
  requirements=${line#*Requirements }
  requirements=${requirements%%; Parent*}
  printf '%s\n' "$requirements" |
    rg -o '(FR|SEC|NFR|EVAL)-[0-9]{3}' |
    LC_ALL=C sort -u > "$actual" || true
  diff -u "$expected" "$actual" >/dev/null ||
    fail "$key has a missing, extra, or duplicate backlog mapping"
}

assert_doc_table_mapping() {
  local path=$1
  local key=$2
  shift 2
  local actual="$tmp/${key}.actual"
  local expected="$tmp/${key}.expected"

  printf '%s\n' "$@" | LC_ALL=C sort -u > "$expected"
  rg '^\|' "$path" |
    rg -o '(FR|SEC|NFR|EVAL)-[0-9]{3}' |
    LC_ALL=C sort -u > "$actual" || true

  diff -u "$expected" "$actual" >/dev/null ||
    fail "$key traceability table does not exactly match its manifest requirements"
}

for spec in FR:85 SEC:42 NFR:30 EVAL:30; do
  prefix=${spec%%:*}
  maximum=${spec##*:}
  number=1
  while ((number <= maximum)); do
    printf '%s-%03d\n' "$prefix" "$number"
    ((number += 1))
  done
done | LC_ALL=C sort > "$tmp/expected"

sed '/^### 9[.]1 Engineering-policy implementation trace$/q' "$prd" |
  rg -o '^\| (FR|SEC|NFR|EVAL)-[0-9]{3} \|' |
  sed -E 's/^\| ([A-Z]+-[0-9]{3}) \|/\1/' |
  LC_ALL=C sort > "$tmp/defined"

rg -o '(FR|SEC|NFR|EVAL)-[0-9]{3}' "$backlog" |
  LC_ALL=C sort -u > "$tmp/referenced"

diff -u "$tmp/expected" "$tmp/defined" >/dev/null ||
  fail 'PRD requirement definitions are missing, duplicated, or unexpected'
diff -u "$tmp/expected" "$tmp/referenced" >/dev/null ||
  fail 'Linear manifest requirement coverage is incomplete or unexpected'

defined_count=$(wc -l < "$tmp/defined" | tr -d ' ')
referenced_count=$(wc -l < "$tmp/referenced" | tr -d ' ')
[[ "$defined_count" == 187 && "$referenced_count" == 187 ]] ||
  fail "expected 187 requirements; found defined=$defined_count referenced=$referenced_count"

assert_leaf_mapping COH-E01-01 FR-001 FR-005 NFR-030
assert_leaf_mapping COH-E01-02 SEC-001 SEC-002 SEC-017 SEC-026
assert_leaf_mapping COH-E01-03 SEC-003 SEC-005 SEC-006 SEC-007 SEC-008

assert_doc_table_mapping "$product_contract" COH-E01-01 FR-001 FR-005 NFR-030
assert_doc_table_mapping "$trust_adr" COH-E01-02 SEC-001 SEC-002 SEC-017 SEC-026
assert_doc_table_mapping "$action_tiers" COH-E01-03 SEC-003 SEC-005 SEC-006 SEC-007 SEC-008

# Match semantic headings with optional section numbering. This deliberately avoids
# coupling verification to a specific PRD outline number.
for heading in \
  'Product definition' 'Problem statement' 'Goals' 'Success measures' 'Personas' \
  'In scope' 'Non-goals' 'Product principles and action authority' 'Architecture' \
  'Functional requirements' 'Security requirements' 'Non-functional requirements' \
  'Failure semantics' 'Evaluation requirements' 'Release milestones and traceability' \
  'Locked assumptions' 'Definition of GA'; do
  require_heading "$prd" "$heading" "PRD semantic heading '$heading'"
done

for heading in \
  'Product decision' 'Personas and authority' 'Supported v1 workflows' \
  'Measurable success outcomes' 'Explicit non-goals' 'Adopted and rejected alternatives' \
  'Request and failure behavior' 'Requirement traceability' 'Approval checklist'; do
  require_heading "$product_contract" "$heading" "COH-E01-01 heading '$heading'"
done

for heading in \
  'Context' 'Decision drivers' 'Decision' 'Architecture and trust-boundary map' \
  'Boundary catalogue' 'Failure semantics' 'Enforceable rules and verification' \
  'Alternatives rejected' 'Non-goals' 'Consequences' \
  'Deployment implications' 'Traceability' 'Change control'; do
  require_heading "$trust_adr" "$heading" "COH-E01-02 heading '$heading'"
done

for heading in \
  'Enforceable implementation rules' 'Required verification matrix' \
  'Completion evidence' 'Change control'; do
  require_heading "$trust_verification" "$heading" \
    "COH-E01-02 companion heading '$heading'"
done

for heading in \
  'Governance metadata' 'Decision' 'Classification precedence' \
  'Normative T0[-–]T4 decision table' 'Approval binding and separation of duties' \
  'Failure, cancellation, and recovery decision table' 'Alternatives considered' \
  'Non-goals' 'Change control' 'Requirement traceability' \
  'Acceptance evidence required by COH-E01-03'; do
  require_heading "$action_tiers" "$heading" "COH-E01-03 heading '$heading'"
done

for path in "$prd" "$product_contract" "$trust_adr" "$trust_verification" "$action_tiers"; do
  if rg -n '\b(TODO|TBD|FIXME)\b' "$path"; then
    fail "unresolved placeholder found in ${path#$root/}"
  fi
done

printf 'PRD trace summary: defined=%d referenced=%d E01 mappings=3 documents=3 missing=0 unexpected=0\n' \
  "$defined_count" "$referenced_count"
