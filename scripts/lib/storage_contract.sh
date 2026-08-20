#!/bin/bash

# Pure storage-containment helpers shared by the native CI entrypoints.

coh_path_within() {
  case "$2/" in
    "$1/"*) return 0 ;;
    *) return 1 ;;
  esac
}

coh_real_existing_directory() {
  [[ -d "$1" && ! -L "$1" ]] || return 1
  (cd -P "$1" && /bin/pwd -P)
}

coh_nearest_existing_parent() {
  local candidate=$1
  while [[ ! -e "${candidate}" && ! -L "${candidate}" ]]; do
    [[ "${candidate}" != "/" ]] || return 1
    candidate=${candidate%/*}
    [[ -n "${candidate}" ]] || candidate=/
  done
  coh_real_existing_directory "${candidate}"
}

# coh_prepare_contained_directory proves the nearest existing parent is under
# an already trusted root before it creates anything, then re-resolves the
# resulting directory to close pre-existing symlink escapes.
coh_prepare_contained_directory() {
  local trusted_root=$1
  local candidate=$2
  local trusted_real parent_real candidate_real
  [[ "${candidate}" == /* && "${candidate}" != *$'\n'* ]] || return 1
  trusted_real="$(coh_real_existing_directory "${trusted_root}")" || return 1
  parent_real="$(coh_nearest_existing_parent "${candidate}")" || return 1
  coh_path_within "${trusted_real}" "${parent_real}" || return 1
  /bin/mkdir -p -- "${candidate}" || return 1
  candidate_real="$(coh_real_existing_directory "${candidate}")" || return 1
  coh_path_within "${trusted_real}" "${candidate_real}" || return 1
  printf '%s\n' "${candidate_real}"
}

# Arguments are pre-collected facts so the decision table can be tested
# without fabricating or modifying host mount state.
coh_validate_mount_facts() {
  local is_directory=$1
  local is_symlink=$2
  local is_mounted=$3
  local root_device=$4
  local volume_device=$5
  [[ "${is_directory}" == true && "${is_symlink}" == false && "${is_mounted}" == true ]] || return 1
  [[ -n "${root_device}" && -n "${volume_device}" && "${root_device}" != "${volume_device}" ]] || return 1
}

coh_require_native_macos_volume() {
  local volume=$1
  local is_directory=false is_symlink=false is_mounted=false root_device volume_device
  [[ -d "${volume}" ]] && is_directory=true
  [[ -L "${volume}" ]] && is_symlink=true
  if /sbin/mount | /usr/bin/awk -v volume="${volume}" '$2 == "on" && $3 == volume { found=1 } END { exit !found }'; then
    is_mounted=true
  fi
  root_device="$(/usr/bin/stat -f '%d' / 2>/dev/null)" || return 1
  volume_device="$(/usr/bin/stat -f '%d' "${volume}" 2>/dev/null)" || return 1
  coh_validate_mount_facts "${is_directory}" "${is_symlink}" "${is_mounted}" "${root_device}" "${volume_device}"
}
