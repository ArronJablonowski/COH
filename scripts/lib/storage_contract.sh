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

coh_path_has_no_symlink_components() {
  local path=$1 current='' component
  [[ "${path}" == /* ]] || return 1
  IFS='/' read -r -a coh_path_components <<< "${path}"
  for component in "${coh_path_components[@]}"; do
    [[ -n "${component}" ]] || continue
    current="${current}/${component}"
    [[ ! -L "${current}" ]] || return 1
  done
  unset coh_path_components
}

coh_file_identity() {
  local path=$1
  if [[ "$(/usr/bin/uname -s)" == "Darwin" ]]; then
    /usr/bin/stat -f '%d:%i:%Lp:%l:%z:%u' "${path}"
  else
    /usr/bin/stat -c '%d:%i:%a:%h:%s:%u' "${path}"
  fi
}

coh_directory_is_private() {
  local path=$1 identity mode links owner
  [[ -d "${path}" && ! -L "${path}" ]] || return 1
  identity="$(coh_file_identity "${path}")" || return 1
  IFS=: read -r _ _ mode links _ owner <<< "${identity}"
  [[ "${owner}" == "$(/usr/bin/id -u)" && "${links}" -ge 1 ]] || return 1
  (( (8#${mode} & 8#022) == 0 ))
}

coh_read_stable_telemetry_mode() {
  local directory=$1 allow_date=${2:-false}
  local before after content mode links size owner
  coh_path_has_no_symlink_components "${directory}" || return 1
  coh_directory_is_private "${directory}" || return 1
  (
    builtin cd -P -- "${directory}" || exit 1
    [[ -f mode && ! -L mode ]] || exit 1
    before="$(coh_file_identity mode)" || exit 1
    IFS=: read -r _ _ mode links size owner <<< "${before}"
    [[ "${owner}" == "$(/usr/bin/id -u)" && "${links}" == 1 ]] || exit 1
    (( (8#${mode} & 8#022) == 0 )) || exit 1
    content="$(/bin/cat mode)" || exit 1
    after="$(coh_file_identity mode)" || exit 1
    [[ "${before}" == "${after}" && "${size}" -le 14 ]] || exit 1
    if [[ "${allow_date}" == true ]]; then
      [[ "${content}" =~ ^off([[:space:]][0-9]{4}-[0-9]{2}-[0-9]{2})?$ ]]
    else
      [[ "${content}" == off && "${mode}" == 600 && "${size}" == 3 ]]
    fi
  )
}

# Publish exact XDG telemetry-off bytes without replacing an existing pathname.
coh_prepare_go_telemetry_mode() {
  local trusted_root=$1 config_root=$2
  local config_real telemetry_directory
  config_real="$(coh_prepare_contained_directory "${trusted_root}" "${config_root}")" || return 1
  telemetry_directory="$(coh_prepare_contained_directory "${config_real}" "${config_real}/go/telemetry")" || return 1
  coh_path_has_no_symlink_components "${telemetry_directory}" || return 1
  coh_directory_is_private "${telemetry_directory}" || return 1
  if ! coh_read_stable_telemetry_mode "${telemetry_directory}" false; then
    (
      local temporary
      builtin cd -P -- "${telemetry_directory}" || exit 1
      temporary="$(/usr/bin/mktemp .mode.XXXXXX)" || exit 1
      trap '/bin/rm -f -- "${temporary}"' EXIT
      /bin/chmod 0600 "${temporary}" || exit 1
      printf off > "${temporary}" || exit 1
      /bin/ln "${temporary}" mode 2>/dev/null || true
    ) || return 1
  fi
  coh_path_has_no_symlink_components "${telemetry_directory}" || return 1
  coh_read_stable_telemetry_mode "${telemetry_directory}" false || return 1
  printf '%s\n' "${telemetry_directory}/mode"
}

coh_ensure_go_telemetry_off() {
  local trusted_root=$1 config_root=$2 native_directory
  if [[ "$(/usr/bin/uname -s)" == "Darwin" ]]; then
    # A scrubbed child with no HOME gives Go no user config directory to mutate.
    [[ -n "${HOME:-}" ]] || return 0
    native_directory="${HOME}/Library/Application Support/go/telemetry"
    coh_read_stable_telemetry_mode "${native_directory}" true
    return
  fi
  coh_prepare_go_telemetry_mode "${trusted_root}" "${config_root}" >/dev/null
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
