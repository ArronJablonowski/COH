#!/bin/bash
set -euo pipefail

network=false
declare -a files=()

while (($#)); do
  case "$1" in
    --network) network=true ;;
    --help)
      printf 'usage: %s [--network] FILE...\n' "$0"
      exit 0
      ;;
    --*)
      printf 'error: unknown option: %s\n' "$1" >&2
      exit 2
      ;;
    *) files+=("$1") ;;
  esac
  shift
done

if ((${#files[@]} == 0)); then
  printf 'error: at least one Markdown file is required\n' >&2
  exit 2
fi

for command in perl sort mktemp; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'error: required command is unavailable: %s\n' "$command" >&2
    exit 2
  }
done

if "$network"; then
  command -v curl >/dev/null 2>&1 || {
    printf 'error: curl is required for --network\n' >&2
    exit 2
  }
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/coh-link-check.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
: > "$tmp/external"

checked=0
failures=0

for file in "${files[@]}"; do
  [[ -f "$file" ]] || {
    printf 'FAIL missing-file %s\n' "$file" >&2
    failures=$((failures + 1))
    continue
  }

  while IFS= read -r target; do
    [[ -n "$target" ]] || continue
    checked=$((checked + 1))
    target=${target#<}
    target=${target%>}

    case "$target" in
      http://*|https://*) printf '%s\n' "$target" >> "$tmp/external" ;;
      mailto:*|\#*) ;;
      *)
        local_path=${target%%#*}
        local_path=${local_path%%\?*}
        [[ -z "$local_path" ]] && continue
        if [[ "$local_path" = /* ]]; then
          resolved=$local_path
        else
          resolved=$(dirname "$file")/$local_path
        fi
        if [[ ! -e "$resolved" ]]; then
          printf 'FAIL local-link %s -> %s\n' "$file" "$target" >&2
          failures=$((failures + 1))
        fi
        ;;
    esac
  done < <(perl -ne 'while (/\]\(([^)]+)\)/g) { print "$1\n" }' "$file")
done

LC_ALL=C sort -u "$tmp/external" > "$tmp/external.unique"
external_count=$(wc -l < "$tmp/external.unique" | tr -d ' ')

if "$network"; then
  while IFS= read -r url; do
    [[ -n "$url" ]] || continue
    if ! code=$(curl -L --silent --show-error --max-time 20 --retry 1 \
      --output /dev/null --write-out '%{http_code}' "$url"); then
      printf 'FAIL external-link %s\n' "$url" >&2
      failures=$((failures + 1))
      continue
    fi
    case "$code" in
      2??|3??|401|403|405|429) ;;
      *)
        printf 'FAIL external-link status=%s %s\n' "$code" "$url" >&2
        failures=$((failures + 1))
        ;;
    esac
  done < "$tmp/external.unique"
fi

printf 'link summary: references=%d unique_external=%d network=%s failures=%d\n' \
  "$checked" "$external_count" "$network" "$failures"
(( failures == 0 ))
