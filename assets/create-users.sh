#!/bin/bash
# Plan by default. Invoke with /bin/bash; compatible with macOS Bash 3.2.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077
fail() { printf 'REFUSED: %s\n' "$*" >&2; exit 1; }
usage() {
    printf '%s\n' 'Usage: /bin/bash assets/create-users.sh --controller-user NAME --controller-uid UID --controller-gid GID --job-user NAME [--job-real-name NAME] --job-uid UID --job-gid GID --owner-user NAME --owner-uid UID [--apply]'
}
# Pure membership check, also usable by callers that already resolved group IDs.
validate_account_groups() {
    local name=$1 other=$2 actual=$3 gid
    for gid in $actual; do
        case "$gid" in 0|20|80|"$other") fail "privileged/shared supplementary group for $name; keep services disabled and reconcile manually" ;; esac
    done
}
create_identity() {
    local name=$1 uid=$2 gid=$3 shell=$4 userhome=$5
    /usr/bin/dscl . -create "/Groups/$name"
    /usr/bin/dscl . -create "/Groups/$name" PrimaryGroupID "$gid"
    /usr/bin/dscl . -create "/Groups/$name" Password '*'
    /usr/bin/dscl . -create "/Users/$name"
    /usr/bin/dscl . -create "/Users/$name" UniqueID "$uid"
    /usr/bin/dscl . -create "/Users/$name" PrimaryGroupID "$gid"
    /usr/bin/dscl . -create "/Users/$name" NFSHomeDirectory "$userhome"
    /usr/bin/dscl . -create "/Users/$name" UserShell "$shell"
}
create_accounts() {
    create_identity "$controller_user" "$controller_uid" "$controller_gid" /usr/bin/false "$prefix/var/controller"
    /usr/bin/dscl . -create "/Users/$controller_user" Password '*'
    /usr/bin/dscl . -create "/Users/$controller_user" IsHidden 1
    create_identity "$job_user" "$job_uid" "$job_gid" /bin/zsh "$home"
    /usr/bin/dscl . -create "/Users/$job_user" RealName "$job_real_name"
    /usr/bin/dscl . -create "/Users/$job_user" AuthenticationAuthority ';ShadowHash;'
}
main() {
apply=false
controller_user='' controller_uid='' controller_gid='' job_user='' job_uid='' job_gid='' owner_user='' owner_uid=''
job_real_name='macserve build'
seen=' '
while [ "$#" -gt 0 ]; do
    flag=$1; shift
    case "$flag" in
        --help) usage; exit 0 ;;
        --apply) [ "$apply" = false ] || fail 'duplicate --apply'; apply=true; continue ;;
        --controller-user|--controller-uid|--controller-gid|--job-user|--job-real-name|--job-uid|--job-gid|--owner-user|--owner-uid) ;;
        *) fail "unknown option: $flag" ;;
    esac
    case "$seen" in *" $flag "*) fail "duplicate option: $flag" ;; esac
    seen="$seen$flag "
    [ "$#" -gt 0 ] || fail "missing value: $flag"
    value=$1; shift
    case "$flag" in
        --controller-user) controller_user=$value ;; --controller-uid) controller_uid=$value ;;
        --controller-gid) controller_gid=$value ;; --job-user) job_user=$value ;;
        --job-uid) job_uid=$value ;; --job-gid) job_gid=$value ;;
        --owner-user) owner_user=$value ;; --owner-uid) owner_uid=$value ;;
        --job-real-name) job_real_name=$value ;;
    esac
done
[ -n "$job_real_name" ] || fail 'job real name must not be empty'
case "$job_real_name" in *[$'\001'-$'\037'$'\177']*) fail 'job real name must not contain control characters' ;; esac
for name in "$controller_user" "$job_user" "$owner_user"; do
    [[ "$name" =~ ^[a-z][a-z0-9_]{0,30}$ ]] || fail 'names must be 1..31 lowercase ASCII letters/digits/underscores, starting with a letter'
    case "$name" in root|wheel|admin|staff|daemon|nobody|operator|everyone|guest) fail 'reserved account/group name' ;; esac
done
for number in "$controller_uid" "$controller_gid" "$job_uid" "$job_gid" "$owner_uid"; do
    [[ "$number" =~ ^[1-9][0-9]{2,8}$ ]] || fail 'IDs must be canonical decimal integers >=501 and <=999999999'
    [ "$number" -ge 501 ] || fail 'IDs below 501 are reserved'
done
if [ "$controller_user" = "$job_user" ] || [ "$controller_user" = "$owner_user" ] || [ "$job_user" = "$owner_user" ]; then
    fail 'account names must differ'
fi
if [ "$controller_uid" = "$job_uid" ] || [ "$controller_uid" = "$owner_uid" ] || [ "$job_uid" = "$owner_uid" ]; then
    fail 'account UIDs must differ'
fi
[ "$controller_gid" != "$job_gid" ] || fail 'dedicated primary GIDs must differ'
prefix=/Library/macserve
home=/Users/$job_user
printf 'PLAN ONLY until explicit --apply: controller %s uid=%s primary-group=%s gid=%s (nonlogin); job %s uid=%s primary-group=%s gid=%s; existing owner %s uid=%s\n' "$controller_user" "$controller_uid" "$controller_user" "$controller_gid" "$job_user" "$job_uid" "$job_user" "$job_gid" "$owner_user" "$owner_uid"
printf '%s\n' 'Create root:wheel 0755 /Library/macserve, bin and config; root:wheel 0711 var.' 'Create controller-owned 0700 var/controller, var/controller/secrets, var/controller/run, var/controller/log.' 'Create root:wheel 0700 var/broker, var/broker/log, var/exports; root:wheel 0711 var/workspaces; root:wheel 0755 health.' "Create job-owned 0700 $home. Controller password disabled; job display name: $job_real_name." "Set the job password privately afterward: sudo dscl . -passwd /Users/$job_user" 'No services, PF, owner ACLs, FileVault, auto-login, or GUI login changed. Plan performs no account/home/service inspection.'
[ "$apply" = true ] || return 0
# Gate BEFORE any host account or filesystem inspection.
[ "$(/usr/bin/uname -s)" = Darwin ] || fail '--apply requires Darwin'
[ "$EUID" -eq 0 ] || fail '--apply requires root'
for tool in /usr/bin/dscl /usr/bin/dscacheutil /usr/bin/id /usr/bin/stat /usr/bin/install /bin/ls; do
    [ -x "$tool" ] || fail "required system tool unavailable: $tool"
done
# Query the search node as well as the local directory: fail closed on directory errors.
users=$(/usr/bin/dscl /Search -list /Users UniqueID) || fail 'cannot enumerate users'
groups=$(/usr/bin/dscl /Search -list /Groups PrimaryGroupID) || fail 'cannot enumerate groups'
local_users=$(/usr/bin/dscl . -list /Users UniqueID) || fail 'cannot enumerate local users'
local_groups=$(/usr/bin/dscl . -list /Groups PrimaryGroupID) || fail 'cannot enumerate local groups'
check_records() {
    local records=$1 name id extra
    while read -r name id extra; do
        [ -n "$name" ] || continue
        if [ -n "$extra" ] || ! [[ "$id" =~ ^-?[0-9]+$ ]]; then
            fail 'ambiguous directory record; review manually'
        fi
        if [ "$name" = "$controller_user" ] || [ "$name" = "$job_user" ]; then
            fail "account/group name collision: $name"
        fi
        case "$2:$id" in "user:$controller_uid"|"user:$job_uid"|"group:$controller_gid"|"group:$job_gid") fail "numeric $2 collision: $id" ;; esac
    done <<< "$records"
}
check_records "$users" user; check_records "$local_users" user
check_records "$groups" group; check_records "$local_groups" group
# Reject dangling supplementary memberships before creating either name.
for node in /Search .; do
    memberships=$(/usr/bin/dscl "$node" -list /Groups GroupMembership) || fail 'cannot enumerate supplementary group membership'
    while read -r group members; do
        for member in $members; do
            if [ "$member" = "$controller_user" ] || [ "$member" = "$job_user" ]; then
                fail "preexisting supplementary membership in $group"
            fi
        done
    done <<< "$memberships"
done
# dscacheutil catches aliases/search-policy records not represented by canonical names.
for name in "$controller_user" "$job_user"; do
    cached=$(/usr/bin/dscacheutil -q user -a name "$name") || fail 'cannot query cached users'
    [ -z "$cached" ] || fail "cached user collision: $name"
    cached=$(/usr/bin/dscacheutil -q group -a name "$name") || fail 'cannot query cached groups'
    [ -z "$cached" ] || fail "cached group collision: $name"
done
[ "$(/usr/bin/id -u "$owner_user")" = "$owner_uid" ] || fail 'owner identity mismatch'
owner_groups=$(/usr/bin/id -G "$owner_user") || fail 'cannot resolve owner groups'
for gid in $owner_groups; do
    if [ "$gid" = "$controller_gid" ] || [ "$gid" = "$job_gid" ]; then
        fail 'primary group shared with owner'
    fi
done
# Existing records must not already reference the proposed unallocated primary groups.
primary_groups=$(/usr/bin/dscl /Search -list /Users PrimaryGroupID) || fail 'cannot enumerate primary groups'
local_primary_groups=$(/usr/bin/dscl . -list /Users PrimaryGroupID) || fail 'cannot enumerate local primary groups'
primary_groups="$primary_groups
$local_primary_groups"
while read -r name gid extra; do
    [ -n "$name" ] || continue
    if [ -n "$extra" ] || ! [[ "$gid" =~ ^-?[0-9]+$ ]]; then
        fail 'ambiguous primary group record'
    fi
    if [ "$gid" = "$controller_gid" ] || [ "$gid" = "$job_gid" ]; then
        fail 'proposed primary group referenced by existing user'
    fi
done <<< "$primary_groups"
for path in /Library /Users; do
    if [ ! -d "$path" ] || [ -L "$path" ]; then
        fail "unsafe parent: $path"
    fi
    [ "$(/usr/bin/stat -f %u "$path")" = 0 ] || fail "parent not root-owned: $path"
    mode=$(/usr/bin/stat -f %Lp "$path")
    (( (8#$mode & 0022) == 0 )) || fail "parent writable by non-root: $path"
    # Deny-only system ACLs cannot grant writes; any allow/unknown ACL needs review.
    acl=$(/bin/ls -lde "$path") || fail 'cannot inspect parent ACL'
    first=true
    while IFS= read -r entry; do
        if [ "$first" = true ]; then first=false; continue; fi
        case "$entry" in *" deny "*) ;; *) fail "parent ACL requires separate manual review: $path" ;; esac
    done <<< "$acl"
done
for path in "$prefix" "$home"; do
    if [ -e "$path" ] || [ -L "$path" ]; then
        fail "existing path: $path"
    fi
done
# There is no rollback: never delete accounts or paths on a partial failure.
# Run only in an exclusive approved administration window; directory checks are not atomic.
report_partial_failure() {
    if [ "$1" -ne 0 ]; then
        printf '%s\n' 'PARTIAL FAILURE: no rollback attempted. Keep services disabled. Inspect only the named new accounts/groups and /Library/macserve plus the proposed job home; reconcile manually before retrying. Existing paths/accounts will cause retry refusal.' >&2
    fi
}
trap 'report_partial_failure "$?"' EXIT
create_accounts
# A new account must not inherit supplementary privileges from a directory policy.
for name in "$controller_user" "$job_user"; do
    actual=$(/usr/bin/id -G "$name")
    if [ "$name" = "$controller_user" ]; then expected=$controller_gid; other=$job_gid; else expected=$job_gid; other=$controller_gid; fi
    [ "$(/usr/bin/id -g "$name")" = "$expected" ] || fail "incorrect primary group for $name"
    validate_account_groups "$name" "$other" "$actual"
done
/usr/bin/install -d -o root -g wheel -m 0755 "$prefix" "$prefix/bin" "$prefix/health"
/usr/bin/install -d -o root -g wheel -m 0755 "$prefix/config"
/usr/bin/install -d -o root -g wheel -m 0711 "$prefix/var" "$prefix/var/workspaces"
/usr/bin/install -d -o "$controller_uid" -g "$controller_gid" -m 0700 "$prefix/var/controller" "$prefix/var/controller/secrets" "$prefix/var/controller/run" "$prefix/var/controller/log"
/usr/bin/install -d -o root -g wheel -m 0700 "$prefix/var/broker" "$prefix/var/broker/log" "$prefix/var/exports"
/usr/bin/install -d -o "$job_uid" -g "$job_gid" -m 0700 "$home"
printf '%s\n' "Created accounts and empty protected directories only. Controller password remains disabled. Set the job password privately afterward: sudo dscl . -passwd /Users/$job_user" 'Install reviewed inputs separately and qualify before enabling anything.'
}
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
