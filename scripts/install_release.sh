#!/bin/bash

set -euo pipefail

gate=${COH_INSTALLGATE_BIN:-}
[[ "${gate}" == /* && -x "${gate}" && -f "${gate}" && ! -L "${gate}" ]] || {
  echo "install_release: a trusted absolute COH_INSTALLGATE_BIN is required" >&2
  exit 64
}

exec "${gate}" "${1:-}" "${2:-}" "${3:-}" "${4:-}"
