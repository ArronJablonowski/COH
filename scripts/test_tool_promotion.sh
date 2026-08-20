#!/bin/bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)"
# shellcheck source=lib/tool_promotion.sh
source "${repo_root}/scripts/lib/tool_promotion.sh"
temporary="$(/usr/bin/mktemp -d "${GOTMPDIR:?GOTMPDIR is required}/coh-promotion-contract.XXXXXX")"
cleanup() { /bin/rm -rf -- "${temporary}"; }
trap cleanup EXIT HUP INT TERM

parent="${temporary}/tools"
/bin/mkdir -p "${parent}/bin" "${temporary}/fresh"
printf 'old\n' > "${parent}/bin/tool"
printf 'new\n' > "${temporary}/fresh/tool"
coh_promote_tool_directory "${temporary}/fresh" "${parent}"
[[ "$(/bin/cat "${parent}/bin/tool")" == new ]] || { echo "promotion did not install the fresh tool" >&2; exit 1; }
coh_recover_tool_promotion "${parent}"
[[ "$(/bin/cat "${parent}/bin/tool")" == old ]] || { echo "interrupted promotion did not roll back" >&2; exit 1; }

/bin/mkdir -p "${temporary}/fresh-final"
printf 'new\n' > "${temporary}/fresh-final/tool"
coh_promote_tool_directory "${temporary}/fresh-final" "${parent}"
coh_finalize_tool_promotion "${parent}"
[[ "$(/bin/cat "${parent}/bin/tool")" == new && ! -e "${parent}/.bin.previous" ]] || { echo "verified promotion did not finalize" >&2; exit 1; }

lock="${temporary}/promotion.lock"
coh_acquire_directory_lock "${lock}" 1
if coh_acquire_directory_lock "${lock}" 1; then
  echo "concurrent promotion lock was bypassed" >&2
  exit 2
fi
/bin/rmdir "${lock}"

echo "Tool promotion recovery tests: passed"
