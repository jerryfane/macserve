#!/bin/bash
# Reviewed bootstrap. Run with /bin/bash; compatible with macOS Bash 3.2.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077
fail() { printf 'REFUSED: %s\n' "$*" >&2; exit 1; }
usage() {
    printf '%s\n' 'Usage: /bin/bash install.sh --env PATH --binary PATH --sha256 LOWERCASE_HEX [--assets PATH] [--apply]' 'Default is a nonprivileged plan. Apply requires Darwin root and root-controlled reviewed env/assets. The expected digest must come from a trusted release channel.'
}
apply=false
env_file='' binary='' sha='' assets=''
seen=' '
while [ "$#" -gt 0 ]; do
    flag=$1; shift
    case "$flag" in
        --help|-h)
            if [ "$#" -ne 0 ] || [ "$seen" != ' ' ]; then
                fail 'help must be used alone'
            fi
            usage; exit 0 ;;
        --apply) [ "$apply" = false ] || fail 'duplicate --apply'; apply=true; continue ;;
        --env|--binary|--sha256|--assets) ;;
        *) fail "unknown option: $flag" ;;
    esac
    case "$seen" in *" $flag "*) fail "duplicate option: $flag" ;; esac
    seen="$seen$flag "
    [ "$#" -gt 0 ] || fail "missing value: $flag"
    value=$1; shift
    [ -n "$value" ] || fail "empty value: $flag"
    case "$flag" in
        --env) env_file=$value ;; --binary) binary=$value ;;
        --sha256) sha=$value ;; --assets) assets=$value ;;
    esac
done
if [ -z "$env_file" ] || [ -z "$binary" ] || [ -z "$sha" ]; then
    usage >&2
    exit 2
fi
[[ "$sha" =~ ^[0-9a-f]{64}$ ]] || fail 'SHA256 must be 64 lowercase hexadecimal characters'
if [ "$apply" = true ]; then
    [ "$(/usr/bin/uname -s)" = Darwin ] || fail '--apply requires Darwin'
    if [ "$EUID" -ne 0 ] || [ "$(/usr/bin/id -ru)" -ne 0 ]; then
        fail '--apply requires real/effective root'
    fi
fi
[ -n "$assets" ] || assets=$(CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")" && pwd -P)
case "$env_file" in /*) ;; *) env_file="$PWD/$env_file" ;; esac
case "$binary" in /*) ;; *) binary="$PWD/$binary" ;; esac
case "$assets" in /*) ;; *) assets="$PWD/$assets" ;; esac
if [ ! -f "$binary" ] || [ -L "$binary" ]; then
    fail 'binary must be a nonsymlink regular file'
fi
[ -x /usr/bin/shasum ] || fail 'required /usr/bin/shasum unavailable'
if [ "$EUID" -eq 0 ]; then
    [ "$(/usr/bin/uname -s)" = Darwin ] || fail 'run non-Darwin plans without root'
    [ "$(/usr/bin/id -ru)" -eq 0 ] || fail 'root planning requires real/effective root'
    # Root plans also execute the verified binary: never trust a user's TMPDIR.
    for parent in / /private /private/var /private/var/root; do
        if [ ! -d "$parent" ] || [ -L "$parent" ]; then
            fail 'unsafe root staging parent'
        fi
        [ "$(/usr/bin/stat -f %u "$parent")" = 0 ] || fail 'staging parent not root-owned'
        mode=$(/usr/bin/stat -f %Lp "$parent")
        (( (8#$mode & 0022) == 0 )) || fail 'staging parent writable by non-root'
        acl=$(/bin/ls -lde "$parent") || fail 'cannot inspect staging parent ACL'
        first=true
        while IFS= read -r entry; do
            if [ "$first" = true ]; then first=false; continue; fi
            case "$entry" in *" deny "*) ;; *) fail 'staging parent ACL requires manual review' ;; esac
        done <<< "$acl"
    done
    stage=$(/usr/bin/mktemp -d /private/var/root/.macserve-bootstrap.XXXXXXXX)
else
    stage=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/macserve-bootstrap.XXXXXXXX")
fi
trap '/bin/rm -rf -- "$stage"' EXIT
/bin/chmod 0700 "$stage"
# Bound a changing source too: never copy an arbitrary-sized file as root.
if ! /bin/dd if="$binary" of="$stage/macserve" bs=1048576 count=257 2>"$stage/copy.log"; then
    /bin/cat "$stage/copy.log" >&2
    fail 'binary copy failed; binary not executed'
fi
binary_size=$(/usr/bin/wc -c < "$stage/macserve")
(( binary_size > 0 && binary_size <= 268435456 )) || fail 'binary must be 1..256 MiB'
/bin/chmod 0600 "$stage/macserve"
actual=$(/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/shasum -a 256 "$stage/macserve")
actual=${actual%% *}
[ "$actual" = "$sha" ] || fail 'binary SHA-256 mismatch; binary not executed'
/bin/chmod 0700 "$stage/macserve"
if [ "$apply" = true ]; then
    /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin GOMAXPROCS=2 HOME=/private/var/root "$stage/macserve" deploy-install --env "$env_file" --binary "$stage/macserve" --sha256 "$sha" --assets "$assets" --apply
else
    /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin GOMAXPROCS=2 "$stage/macserve" deploy-install --env "$env_file" --binary "$stage/macserve" --sha256 "$sha" --assets "$assets"
fi
