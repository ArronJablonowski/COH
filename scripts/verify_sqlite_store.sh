#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}

for path in \
  "$root/internal/persistence/sqlite/config.go" \
  "$root/internal/persistence/sqlite/schema.go" \
  "$root/internal/persistence/sqlite/transaction.go" \
  "$root/internal/persistence/sqlite/outbox.go" \
  "$root/internal/persistence/sqlite/migration.go" \
  "$root/internal/persistence/sqlite/backup.go" \
  "$root/internal/persistence/sqlite/sqlite_test.go" \
  "$root/internal/persistence/storetest/conformance.go" \
  "$root/docs/design/sqlite-workstation-store.md"; do
  [[ -f "$path" ]] || {
    printf 'error: SQLite store input is missing: %s\n' "$path" >&2
    exit 2
  }
done

export COH_NATIVE_STORAGE_ROOT=${COH_NATIVE_STORAGE_ROOT:-$(dirname "$root")}
export COH_TOOLCHAIN_ROOT=${COH_TOOLCHAIN_ROOT:-$(dirname "$root")/COH-toolchains}
# shellcheck source=lib/go_ssd_env.sh
source "$root/scripts/lib/go_ssd_env.sh"

"$COH_GO_ROOT/bin/go" test -count=1 -v \
  "$root/internal/persistence/sqlite" \
  "$root/internal/persistence/storetest" \
  "$root/internal/workflow"
"$COH_GO_ROOT/bin/go" test -count=1 -race \
  "$root/internal/persistence/sqlite" \
  "$root/internal/persistence/storetest"
CGO_ENABLED=0 "$COH_GO_ROOT/bin/go" test -count=1 \
  "$root/internal/persistence/sqlite"
"$COH_GO_ROOT/bin/go" vet \
  "$root/internal/persistence/sqlite" \
  "$root/internal/persistence/storetest"
"$root/scripts/check_go_architecture.sh"

printf '%s\n' \
  'sqlite-store summary: transactions=atomic wal=enabled recovery=abrupt-process migrations=registered outbox=replay-safe backups=digest-verified cgo=disabled conformance=passed failures=0'
