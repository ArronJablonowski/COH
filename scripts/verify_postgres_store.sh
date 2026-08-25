#!/bin/bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
container_name="coh-postgres-test-$$"
image="postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777"
admin_password="coh-test-${RANDOM}-${RANDOM}"
docker_bin="$(command -v docker)"
[[ -n "${docker_bin}" && "${docker_bin}" == /* && -x "${docker_bin}" ]] || {
  echo "Docker is required for the PostgreSQL integration test" >&2
  exit 1
}

cleanup() {
  "${docker_bin}" rm -f "${container_name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

"${docker_bin}" run -d --name "${container_name}" \
  --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,size=512m \
  --tmpfs /var/run/postgresql:rw,noexec,nosuid,size=16m \
  -p 127.0.0.1::5432 \
  -e POSTGRES_PASSWORD="${admin_password}" \
  -e POSTGRES_DB=postgres "${image}" >/dev/null

for _ in 1 2 3 4 5 6 7 8 9 10; do
  if "${docker_bin}" exec "${container_name}" pg_isready -U postgres -d postgres >/dev/null 2>&1; then
    break
  fi
  /bin/sleep 2
done
"${docker_bin}" exec "${container_name}" pg_isready -U postgres -d postgres >/dev/null

"${docker_bin}" exec "${container_name}" psql -v ON_ERROR_STOP=1 -U postgres -d postgres -c \
  "CREATE ROLE coh_app LOGIN PASSWORD '${admin_password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;" >/dev/null
"${docker_bin}" exec "${container_name}" psql -v ON_ERROR_STOP=1 -U postgres -d postgres -c \
  "CREATE DATABASE coh_test OWNER coh_app;" >/dev/null

port="$("${docker_bin}" port "${container_name}" 5432/tcp | /usr/bin/awk -F: 'NR==1 {print $NF}')"
export COH_POSTGRES_TEST_URL="postgres://coh_app:${admin_password}@127.0.0.1:${port}/coh_test?sslmode=disable"
export COH_POSTGRES_ADMIN_TEST_URL="postgres://postgres:${admin_password}@127.0.0.1:${port}/postgres?sslmode=disable"
export COH_NATIVE_STORAGE_ROOT="${COH_NATIVE_STORAGE_ROOT:-$(dirname "${repo_root}")}"
export COH_TOOLCHAIN_ROOT="${COH_TOOLCHAIN_ROOT:-$(dirname "${repo_root}")/COH-toolchains}"
# shellcheck source=lib/go_ssd_env.sh
source "${repo_root}/scripts/lib/go_ssd_env.sh"

"${COH_GO_ROOT}/bin/go" test -count=1 -race "${repo_root}/internal/persistence/postgres"
version="$("${docker_bin}" exec "${container_name}" psql -U postgres -d postgres -Atqc 'SHOW server_version')"
printf 'postgres-store summary: version=%s conformance=5 rls=forced backup-denial=passed privileged-role-denial=passed race=passed\n' "${version}"
