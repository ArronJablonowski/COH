#!/bin/bash

coh_acquire_directory_lock() {
  local lock=$1
  local attempts=$2
  local count
  for ((count=0; count<attempts; count++)); do
    if /bin/mkdir "${lock}" 2>/dev/null; then
      return 0
    fi
    /bin/sleep 0.25
  done
  return 1
}

coh_recover_tool_promotion() {
  local parent=$1
  local destination="${parent}/bin"
  local previous="${parent}/.bin.previous"
  local stale
  [[ -d "${parent}" && ! -L "${parent}" ]] || return 1
  if [[ -e "${previous}" || -L "${previous}" ]]; then
    [[ -d "${previous}" && ! -L "${previous}" ]] || return 1
    if [[ -e "${destination}" || -L "${destination}" ]]; then
      [[ -d "${destination}" && ! -L "${destination}" ]] || return 1
      /bin/rm -rf -- "${destination}" || return 1
    fi
    /bin/mv "${previous}" "${destination}" || return 1
  fi
  while IFS= read -r stale; do
    [[ -d "${stale}" && ! -L "${stale}" ]] || return 1
    /bin/rm -rf -- "${stale}" || return 1
  done < <(/usr/bin/find "${parent}" -mindepth 1 -maxdepth 1 -type d -name '.bin.new.*' -print)
}

coh_promote_tool_directory() {
  local fresh=$1
  local parent=$2
  local destination="${parent}/bin"
  local previous="${parent}/.bin.previous"
  local staging="${parent}/.bin.new.$$"
  [[ -d "${fresh}" && ! -L "${fresh}" && -d "${parent}" && ! -L "${parent}" ]] || return 1
  [[ ! -e "${staging}" && ! -L "${staging}" && ! -e "${previous}" && ! -L "${previous}" ]] || return 1
  /bin/mv "${fresh}" "${staging}" || return 1
  if [[ -e "${destination}" || -L "${destination}" ]]; then
    [[ -d "${destination}" && ! -L "${destination}" ]] || return 1
    /bin/mv "${destination}" "${previous}" || return 1
  fi
  if ! /bin/mv "${staging}" "${destination}"; then
    [[ ! -d "${previous}" ]] || /bin/mv "${previous}" "${destination}"
    return 1
  fi
}

coh_finalize_tool_promotion() {
  local parent=$1
  local previous="${parent}/.bin.previous"
  if [[ -e "${previous}" || -L "${previous}" ]]; then
    [[ -d "${previous}" && ! -L "${previous}" ]] || return 1
    /bin/rm -rf -- "${previous}"
  fi
}
