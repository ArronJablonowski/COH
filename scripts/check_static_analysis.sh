#!/bin/bash

set -euo pipefail

config="$(/usr/bin/find . -name staticcheck.conf -type f -print -quit)"
if [[ -n "${config}" ]]; then
  echo "Staticcheck configuration is closed; repository overrides are forbidden" >&2
  exit 2
fi

"${GOBIN:?GOBIN is required}/staticcheck" -checks=all -go=1.26 -tests=true ./...
