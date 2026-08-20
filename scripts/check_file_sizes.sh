#!/bin/bash
set -euo pipefail

root=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}

if [[ ! -d "$root" ]]; then
  printf 'error: repository root does not exist: %s\n' "$root" >&2
  exit 2
fi

cd "$root"

warning_limit=500
file_limit=800
script_limit=300
warnings=0
failures=0
checked=0

is_script() {
  case "$1" in
    scripts/*|*.sh|*.bash|*.zsh|*.py|*.rb|*.pl) return 0 ;;
    *) return 1 ;;
  esac
}

while IFS= read -r path; do
  [[ -f "$path" ]] || continue
  grep -Iq . "$path" 2>/dev/null || continue

  lines=$(wc -l < "$path" | tr -d ' ')
  checked=$((checked + 1))

  if is_script "$path" && (( lines > script_limit )); then
    printf 'FAIL script-size %s: %d > %d lines\n' "$path" "$lines" "$script_limit" >&2
    failures=$((failures + 1))
    continue
  fi

  if (( lines > file_limit )); then
    printf 'FAIL file-size %s: %d > %d lines\n' "$path" "$lines" "$file_limit" >&2
    failures=$((failures + 1))
  elif (( lines > warning_limit )); then
    printf 'WARN file-size %s: %d > %d lines\n' "$path" "$lines" "$warning_limit" >&2
    warnings=$((warnings + 1))
  fi
done < <(git ls-files --cached --others --exclude-standard | LC_ALL=C sort)

printf 'file-size summary: checked=%d warnings=%d failures=%d\n' "$checked" "$warnings" "$failures"
(( failures == 0 ))
