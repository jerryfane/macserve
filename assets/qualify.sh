#!/bin/bash
# Thin wrapper for the installed, root-reviewed executable. Never source deploy.env.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export GOMAXPROCS=2
script_dir=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")" && pwd -P)
binary="$script_dir/macserve"
if [[ "${1:-}" == "--binary" ]]; then
  if [[ $# -lt 3 ]]; then
    printf '%s\n' 'usage: qualify.sh [--binary /absolute/macserve] COMMAND [options]' >&2
    exit 2
  fi
  binary=$2
  shift 2
fi
case "${1:-}" in
  plan|begin|probe|canary|stage-policy|collect|attest|approve) ;;
  *)
    printf '%s\n' 'qualify.sh: expected a recognized qualification subcommand; raw commands are refused' >&2
    exit 2
    ;;
esac
if [[ "$binary" != /* || ! -f "$binary" || ! -x "$binary" || -L "$binary" ]]; then
  printf '%s\n' 'qualify.sh: expected a reviewed absolute executable (installed adjacent macserve by default)' >&2
  exit 1
fi
if [[ "$EUID" -eq 0 ]]; then
  [[ "$(/usr/bin/uname -s)" == Darwin && "$(/usr/bin/id -ru)" -eq 0 ]] || {
    printf '%s\n' 'qualify.sh: privileged commands require actual Darwin root' >&2
    exit 1
  }
  [[ "$binary" == /Library/macserve/bin/macserve ]] || {
    printf '%s\n' 'qualify.sh: root must use the fixed installed executable; --binary is for unprivileged use' >&2
    exit 1
  }
  for path in / /Library /Library/macserve /Library/macserve/bin "$binary"; do
    [[ ! -L "$path" && "$(/usr/bin/stat -f %u "$path")" == 0 ]] || exit 1
    mode=$(/usr/bin/stat -f %Lp "$path")
    (( (8#$mode & 0022) == 0 )) || {
      printf '%s\n' 'qualify.sh: executable or ancestor is writable by non-root' >&2
      exit 1
    }
    acl=$(/bin/ls -lde "$path") || exit 1
    first=true
    while IFS= read -r entry; do
      if [[ "$first" == true ]]; then first=false; continue; fi
      case "$entry" in *" deny "*) ;; *)
        printf '%s\n' 'qualify.sh: executable or ancestor ACL requires review' >&2
        exit 1 ;;
      esac
    done <<< "$acl"
  done
fi
exec "$binary" qualify "$@"
