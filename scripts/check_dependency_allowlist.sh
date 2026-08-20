#!/bin/bash

set -euo pipefail

allow=${1:?dependency allowlist is required}
actual=${2:?module inventory is required}
if ! /usr/bin/diff -u <(/usr/bin/grep -Ev '^[[:space:]]*(#|$)' "${allow}") "${actual}"; then
  echo "Go module inventory differs from the closed dependency allowlist" >&2
  exit 2
fi
