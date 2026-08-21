#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
verifier="$root/scripts/verify_domain_contract.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/coh-domain-contract-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

make_fixture() {
  local name=$1
  local destination="$tmp/$name"
  mkdir -p "$destination/contracts/domain/v1"
  cp -R "$root/contracts/domain/v1/." "$destination/contracts/domain/v1/"
  printf '%s\n' "$destination"
}

expect_failure() {
  local name=$1
  local fixture=$2
  if "$verifier" "$fixture" >"$tmp/$name.out" 2>&1; then
    printf 'FAIL %s: invalid fixture was accepted\n' "$name" >&2
    exit 1
  fi
  printf 'ok: %s rejected\n' "$name"
}

positive=$(make_fixture positive)
"$verifier" "$positive"
printf 'ok: current common envelope accepted\n'

unknown_kind=$(make_fixture unknown-kind)
jq '.kind = "invented_authority"' \
  "$unknown_kind/contracts/domain/v1/fixtures/envelope.valid.json" \
  > "$unknown_kind/contracts/domain/v1/fixtures/envelope.new"
mv "$unknown_kind/contracts/domain/v1/fixtures/envelope.new" \
  "$unknown_kind/contracts/domain/v1/fixtures/envelope.valid.json"
expect_failure unknown-kind "$unknown_kind"

bad_registry=$(make_fixture bad-registry)
jq '.kinds += ["case"]' \
  "$bad_registry/contracts/domain/v1/contract-registry.json" \
  > "$bad_registry/contracts/domain/v1/registry.new"
mv "$bad_registry/contracts/domain/v1/registry.new" \
  "$bad_registry/contracts/domain/v1/contract-registry.json"
expect_failure bad-registry "$bad_registry"

printf 'verify_domain_contract tests: 1 positive, 2 negative, failures=0\n'
