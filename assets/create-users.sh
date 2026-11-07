#!/bin/bash
# Plan by default. Invoke with /bin/bash; compatible with macOS Bash 3.2.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
umask 077
fail() { printf 'REFUSED: %s\n' "$*" >&2; exit 1; }
usage() {
    printf '%s\n' 'Usage: /bin/bash assets/create-users.sh --controller-user NAME --controller-uid UID --controller-gid GID --job-user NAME [--job-real-name NAME] --job-uid UID --job-gid GID --owner-user NAME --owner-uid UID [--signer-uid UID --signer-gid GID --signrpc-gid GID [--signer-only]] [--keyholder-uid UID --keyholder-gid GID --keyrpc-gid GID [--keyholder-only]] [--apply]' '--signer-only adds the signer account, groups and directories to an existing installation of the same named accounts.' '--keyholder-only adds the keyholder account, groups and directories to an existing installation, or re-verifies them and their directories when the keyholder account already exists.'
}
# Pure membership check, also usable by callers that already resolved group IDs.
validate_account_groups() {
    local name=$1 other=$2 actual=$3 gid
    for gid in $actual; do
        case "$gid" in 0|20|80|"$other") fail "privileged/shared supplementary group for $name; keep services disabled and reconcile manually" ;; esac
    done
}
create_group() {
    local name=$1 gid=$2
    /usr/bin/dscl . -create "/Groups/$name"
    /usr/bin/dscl . -create "/Groups/$name" PrimaryGroupID "$gid"
    /usr/bin/dscl . -create "/Groups/$name" Password '*'
}
create_identity() {
    local name=$1 uid=$2 gid=$3 shell=$4 userhome=$5
    create_group "$name" "$gid"
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
    create_group "$job_user" "$job_gid"
    /usr/sbin/sysadminctl -addUser "$job_user" -fullName "$job_real_name" -UID "$job_uid" -GID "$job_gid" -shell /bin/zsh -home "$home" -password -
}
# sysadminctl can exit successfully without creating the requested account.
# Verify specific record fields before provisioning or changing directory ownership.
validate_created_accounts() {
    local name expected_uid expected_gid other actual gid without_staff has_staff record
    for name in "$controller_user" "$job_user"; do
        if [ "$name" = "$controller_user" ]; then
            expected_uid=$controller_uid expected_gid=$controller_gid other=$job_gid
        else
            expected_uid=$job_uid expected_gid=$job_gid other=$controller_gid
        fi
        [ "$(/usr/bin/id -u "$name")" = "$expected_uid" ] || fail "incorrect UID for $name"
        [ "$(/usr/bin/id -g "$name")" = "$expected_gid" ] || fail "incorrect primary group for $name"
        actual=$(/usr/bin/id -G "$name") || fail "cannot resolve groups for $name"
        if [ "$name" = "$job_user" ]; then
            record=$(/usr/bin/dscl . -read "/Users/$name" UniqueID) || fail 'cannot read job UID'
            [ "$record" = "UniqueID: $job_uid" ] || fail 'incorrect job UID record'
            record=$(/usr/bin/dscl . -read "/Users/$name" PrimaryGroupID) || fail 'cannot read job primary group'
            [ "$record" = "PrimaryGroupID: $job_gid" ] || fail 'incorrect job primary group record'
            record=$(/usr/bin/dscl . -read "/Users/$name" NFSHomeDirectory) || fail 'cannot read job home'
            [ "$record" = "NFSHomeDirectory: $home" ] || fail 'incorrect job home record'
            record=$(/usr/bin/dscl . -read "/Users/$name" UserShell) || fail 'cannot read job shell'
            [ "$record" = 'UserShell: /bin/zsh' ] || fail 'incorrect job shell record'
            # Refuse admin/other prohibited memberships before removing staff.
            without_staff='' has_staff=false
            for gid in $actual; do
                if [ "$gid" = 20 ]; then has_staff=true; else without_staff="$without_staff $gid"; fi
            done
            validate_account_groups "$name" "$other" "$without_staff"
            if [ "$has_staff" = true ]; then
                /usr/sbin/dseditgroup -o edit -d "$job_user" -t user staff || fail 'cannot remove new job user from staff'
                actual=$(/usr/bin/id -G "$name") || fail 'cannot re-read job groups'
            fi
        fi
        validate_account_groups "$name" "$other" "$actual"
    done
    # Listing avoids treating an arbitrary -read failure as a missing attribute.
    local hidden_records hidden_name hidden_value found=false
    hidden_records=$(/usr/bin/dscl . -list /Users IsHidden) || fail 'cannot enumerate login visibility'
    while read -r hidden_name hidden_value; do
        if [ "$hidden_name" = "$job_user" ]; then
            [ "$found" = false ] || fail 'ambiguous job login visibility'
            found=true
            [ -z "$hidden_value" ] || fail 'job user has IsHidden set'
        fi
    done <<< "$hidden_records"
    [ "$found" = true ] || fail 'cannot find job login visibility'
}
# The signer is a hidden nonlogin system account with its own primary group;
# the RPC group admits exactly the controller and the signer to the socket
# and inbox directories. The job account belongs to neither group.
create_signer() {
    create_identity "$signer_user" "$signer_uid" "$signer_gid" /usr/bin/false "$prefix/var/signer"
    /usr/bin/dscl . -create "/Users/$signer_user" Password '*'
    /usr/bin/dscl . -create "/Users/$signer_user" IsHidden 1
    create_group "$signrpc_group" "$signrpc_gid"
    /usr/sbin/dseditgroup -o edit -a "$controller_user" -t user "$signrpc_group"
    /usr/sbin/dseditgroup -o edit -a "$signer_user" -t user "$signrpc_group"
}
validate_signer_accounts() {
    validate_daemon_accounts signer "$signer_user" "$signer_uid" "$signer_gid" "$signrpc_group" "$signrpc_gid" "$prefix/var/signer"
}
# A daemon account (signer or keyholder): exact UID, primary group, shell
# and home; no privileged, job or controller group; in its RPC group, which
# holds exactly the controller and the daemon; the controller is not in the
# daemon's own group and the job account is in neither.
validate_daemon_accounts() {
    local role=$1 daemon_user=$2 daemon_uid=$3 daemon_gid=$4 rpc_group=$5 rpc_gid=$6 daemon_home=$7
    local record actual gid has_rpc memberships group members found=false
    [ "$(/usr/bin/id -u "$daemon_user")" = "$daemon_uid" ] || fail "incorrect UID for $daemon_user"
    [ "$(/usr/bin/id -g "$daemon_user")" = "$daemon_gid" ] || fail "incorrect primary group for $daemon_user"
    record=$(/usr/bin/dscl . -read "/Users/$daemon_user" UserShell) || fail "cannot read $role shell"
    [ "$record" = 'UserShell: /usr/bin/false' ] || fail "incorrect $role shell record"
    record=$(/usr/bin/dscl . -read "/Users/$daemon_user" NFSHomeDirectory) || fail "cannot read $role home"
    [ "$record" = "NFSHomeDirectory: $daemon_home" ] || fail "incorrect $role home record"
    actual=$(/usr/bin/id -G "$daemon_user") || fail "cannot resolve groups for $daemon_user"
    has_rpc=false
    for gid in $actual; do
        case "$gid" in 0|20|80|"$job_gid"|"$controller_gid") fail "privileged/shared supplementary group for $daemon_user; keep services disabled and reconcile manually" ;; esac
        if [ "$gid" = "$rpc_gid" ]; then has_rpc=true; fi
    done
    [ "$has_rpc" = true ] || fail "$daemon_user is not a member of $rpc_group"
    actual=$(/usr/bin/id -G "$controller_user") || fail "cannot resolve groups for $controller_user"
    has_rpc=false
    for gid in $actual; do
        [ "$gid" != "$daemon_gid" ] || fail "$controller_user must not belong to $daemon_user"
        if [ "$gid" = "$rpc_gid" ]; then has_rpc=true; fi
    done
    [ "$has_rpc" = true ] || fail "$controller_user is not a member of $rpc_group"
    actual=$(/usr/bin/id -G "$job_user") || fail "cannot resolve groups for $job_user"
    for gid in $actual; do
        case "$gid" in "$daemon_gid"|"$rpc_gid") fail "job user belongs to a $role group; keep services disabled and reconcile manually" ;; esac
    done
    # Exact recorded membership: the controller and the daemon, nobody else.
    memberships=$(/usr/bin/dscl . -list /Groups GroupMembership) || fail "cannot enumerate $role group membership"
    while read -r group members; do
        if [ "$group" = "$rpc_group" ]; then
            [ "$found" = false ] || fail "ambiguous $rpc_group membership"
            found=true
            [ "$members" = "$controller_user $daemon_user" ] || fail "unexpected $rpc_group membership"
        elif [ "$group" = "$daemon_user" ] && [ -n "$members" ]; then
            fail "unexpected $daemon_user group membership"
        fi
    done <<< "$memberships"
    [ "$found" = true ] || fail "cannot find $rpc_group membership"
}
provision_signer_directories() {
    /usr/bin/install -d -o root -g wheel -m 0755 "$prefix/signer-profiles"
    /usr/bin/install -d -o "$signer_uid" -g "$signer_gid" -m 0700 "$prefix/var/signer" "$prefix/var/signer/keychain" "$prefix/var/signer/key" "$prefix/var/signer/work" "$prefix/var/signer/log"
    /usr/bin/install -d -o "$signer_uid" -g "$signrpc_gid" -m 0750 "$prefix/var/signer-run"
    /usr/bin/install -d -o "$controller_uid" -g "$signrpc_gid" -m 0750 "$prefix/var/signer-inbox"
}
# The keyholder is a hidden nonlogin system account with its own primary
# group; it holds the job receipt key and the GitHub App key. The RPC group
# admits exactly the controller and the keyholder to its socket directory.
# The job account belongs to neither group.
create_keyholder() {
    create_identity "$keyholder_user" "$keyholder_uid" "$keyholder_gid" /usr/bin/false "$prefix/var/keyholder"
    /usr/bin/dscl . -create "/Users/$keyholder_user" Password '*'
    /usr/bin/dscl . -create "/Users/$keyholder_user" IsHidden 1
    create_group "$keyrpc_group" "$keyrpc_gid"
    /usr/sbin/dseditgroup -o edit -a "$controller_user" -t user "$keyrpc_group"
    /usr/sbin/dseditgroup -o edit -a "$keyholder_user" -t user "$keyrpc_group"
}
validate_keyholder_accounts() {
    validate_daemon_accounts keyholder "$keyholder_user" "$keyholder_uid" "$keyholder_gid" "$keyrpc_group" "$keyrpc_gid" "$prefix/var/keyholder"
}
# The keyholder's directories; install -d also re-applies owner and mode to
# a directory a resumed --keyholder-only run finds (never a symlink).
keyholder_directories() {
    printf '%s\n' "$prefix/var/keyholder" "$prefix/var/keyholder/secrets" "$prefix/var/keyholder/receipts" "$prefix/var/keyholder/release" "$prefix/var/keyholder/log" "$prefix/var/keyholder-run"
}
provision_keyholder_directories() {
    local path
    for path in $(keyholder_directories); do
        if [ -L "$path" ] || { [ -e "$path" ] && [ ! -d "$path" ]; }; then
            fail "unsafe keyholder directory: $path"
        fi
    done
    /usr/bin/install -d -o "$keyholder_uid" -g "$keyholder_gid" -m 0700 "$prefix/var/keyholder" "$prefix/var/keyholder/secrets" "$prefix/var/keyholder/receipts" "$prefix/var/keyholder/release" "$prefix/var/keyholder/log"
    /usr/bin/install -d -o "$keyholder_uid" -g "$keyrpc_gid" -m 0750 "$prefix/var/keyholder-run"
}
main() {
apply=false signer_only=false keyholder_only=false
controller_user='' controller_uid='' controller_gid='' job_user='' job_uid='' job_gid='' owner_user='' owner_uid=''
signer_uid='' signer_gid='' signrpc_gid=''
signer_user=_macserve_sign signrpc_group=_macserve_signrpc
keyholder_uid='' keyholder_gid='' keyrpc_gid=''
keyholder_user=_macserve_key keyrpc_group=_macserve_keyrpc
job_real_name='macserve build'
seen=' '
while [ "$#" -gt 0 ]; do
    flag=$1; shift
    case "$flag" in
        --help) usage; exit 0 ;;
        --apply) [ "$apply" = false ] || fail 'duplicate --apply'; apply=true; continue ;;
        --signer-only) [ "$signer_only" = false ] || fail 'duplicate --signer-only'; signer_only=true; continue ;;
        --keyholder-only) [ "$keyholder_only" = false ] || fail 'duplicate --keyholder-only'; keyholder_only=true; continue ;;
        --controller-user|--controller-uid|--controller-gid|--job-user|--job-real-name|--job-uid|--job-gid|--owner-user|--owner-uid|--signer-uid|--signer-gid|--signrpc-gid|--keyholder-uid|--keyholder-gid|--keyrpc-gid) ;;
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
        --signer-uid) signer_uid=$value ;; --signer-gid) signer_gid=$value ;; --signrpc-gid) signrpc_gid=$value ;;
        --keyholder-uid) keyholder_uid=$value ;; --keyholder-gid) keyholder_gid=$value ;; --keyrpc-gid) keyrpc_gid=$value ;;
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
# The signer is all-or-nothing: three system IDs, or none and no --signer-only.
signer=false
if [ -n "$signer_uid$signer_gid$signrpc_gid" ]; then
    for number in "$signer_uid" "$signer_gid" "$signrpc_gid"; do
        [[ "$number" =~ ^[2-4][0-9]{2}$ ]] || fail 'signer IDs must be canonical decimal system IDs 200..499'
    done
    [ "$signer_gid" != "$signrpc_gid" ] || fail 'signer and signer RPC GIDs must differ'
    signer=true
fi
if [ "$signer_only" = true ] && [ "$signer" = false ]; then
    fail '--signer-only requires --signer-uid, --signer-gid and --signrpc-gid'
fi
# The keyholder is all-or-nothing too, with IDs distinct from the signer's.
keyholder=false
if [ -n "$keyholder_uid$keyholder_gid$keyrpc_gid" ]; then
    for number in "$keyholder_uid" "$keyholder_gid" "$keyrpc_gid"; do
        [[ "$number" =~ ^[2-4][0-9]{2}$ ]] || fail 'keyholder IDs must be canonical decimal system IDs 200..499'
    done
    [ "$keyholder_gid" != "$keyrpc_gid" ] || fail 'keyholder and keyholder RPC GIDs must differ'
    if [ "$signer" = true ]; then
        [ "$keyholder_uid" != "$signer_uid" ] || fail 'keyholder and signer UIDs must differ'
        for number in "$keyholder_gid" "$keyrpc_gid"; do
            case "$number" in "$signer_gid"|"$signrpc_gid") fail 'keyholder and signer GIDs must differ' ;; esac
        done
    fi
    keyholder=true
fi
if [ "$keyholder_only" = true ] && [ "$keyholder" = false ]; then
    fail '--keyholder-only requires --keyholder-uid, --keyholder-gid and --keyrpc-gid'
fi
if [ "$keyholder_only" = true ] && { [ "$signer_only" = true ] || [ "$signer" = true ]; }; then
    fail '--keyholder-only adds only the keyholder; add the signer in a separate run'
fi
prefix=/Library/macserve
home=/Users/$job_user
# Names and numbers this run creates; every one must be unused.
if [ "$signer_only" = true ] || [ "$keyholder_only" = true ]; then
    new_names='' new_uids='' new_gids=''
else
    new_names="$controller_user $job_user" new_uids="$controller_uid $job_uid" new_gids="$controller_gid $job_gid"
fi
if [ "$signer" = true ]; then
    new_names="$new_names $signer_user $signrpc_group" new_uids="$new_uids $signer_uid" new_gids="$new_gids $signer_gid $signrpc_gid"
fi
if [ "$keyholder" = true ]; then
    new_names="$new_names $keyholder_user $keyrpc_group" new_uids="$new_uids $keyholder_uid" new_gids="$new_gids $keyholder_gid $keyrpc_gid"
fi
if [ "$keyholder_only" = true ]; then
    printf 'PLAN ONLY until explicit --apply: add the keyholder to the existing installation of controller %s uid=%s gid=%s, job %s uid=%s gid=%s, owner %s uid=%s; when %s already exists, re-verify it and its directories instead\n' "$controller_user" "$controller_uid" "$controller_gid" "$job_user" "$job_uid" "$job_gid" "$owner_user" "$owner_uid" "$keyholder_user"
elif [ "$signer_only" = true ]; then
    printf 'PLAN ONLY until explicit --apply: add the signer to the existing installation of controller %s uid=%s gid=%s, job %s uid=%s gid=%s, owner %s uid=%s\n' "$controller_user" "$controller_uid" "$controller_gid" "$job_user" "$job_uid" "$job_gid" "$owner_user" "$owner_uid"
else
    printf 'PLAN ONLY until explicit --apply: controller %s uid=%s primary-group=%s gid=%s (nonlogin); job %s uid=%s primary-group=%s gid=%s; existing owner %s uid=%s\n' "$controller_user" "$controller_uid" "$controller_user" "$controller_gid" "$job_user" "$job_uid" "$job_user" "$job_gid" "$owner_user" "$owner_uid"
    printf '%s\n' 'Create root:wheel 0755 /Library/macserve, bin and config; root:wheel 0711 var.' 'Create controller-owned 0700 var/controller, var/controller/secrets, var/controller/run, var/controller/log.' 'Create root:wheel 0700 var/broker, var/broker/log, var/exports; root:wheel 0711 var/workspaces; root:wheel 0755 health.' "Create job-owned 0700 $home. Controller password disabled; job display name: $job_real_name." 'Create the job account with sysadminctl and enter its password interactively; remove any inherited staff membership and verify identity, groups and login visibility before directory provisioning.'
fi
if [ "$signer" = true ]; then
    printf 'Create signer %s uid=%s primary-group=%s gid=%s (hidden, nonlogin, password disabled); RPC group %s gid=%s with members %s and %s only; the job account joins neither group.\n' "$signer_user" "$signer_uid" "$signer_user" "$signer_gid" "$signrpc_group" "$signrpc_gid" "$controller_user" "$signer_user"
    printf '%s\n' 'Create root:wheel 0755 signer-profiles; signer-owned 0700 var/signer, var/signer/keychain, var/signer/key, var/signer/work, var/signer/log.' "Create $signer_user:$signrpc_group 0750 var/signer-run and $controller_user:$signrpc_group 0750 var/signer-inbox."
fi
if [ "$keyholder" = true ]; then
    printf 'Create keyholder %s uid=%s primary-group=%s gid=%s (hidden, nonlogin, password disabled); RPC group %s gid=%s with members %s and %s only; the job account joins neither group.\n' "$keyholder_user" "$keyholder_uid" "$keyholder_user" "$keyholder_gid" "$keyrpc_group" "$keyrpc_gid" "$controller_user" "$keyholder_user"
    printf '%s\n' 'Create keyholder-owned 0700 var/keyholder, var/keyholder/secrets, var/keyholder/receipts, var/keyholder/release, var/keyholder/log.' "Create $keyholder_user:$keyrpc_group 0750 var/keyholder-run."
fi
printf '%s\n' 'No services, PF, owner ACLs, FileVault, auto-login, or GUI login changed. Plan performs no account/home/service inspection.'
[ "$apply" = true ] || return 0
# Gate BEFORE any host account or filesystem inspection.
if [ "$signer_only" = false ] && [ "$keyholder_only" = false ]; then
    [ -t 0 ] || fail '--apply requires interactive stdin for the sysadminctl password prompt'
fi
[ "$(/usr/bin/uname -s)" = Darwin ] || fail '--apply requires Darwin'
[ "$EUID" -eq 0 ] || fail '--apply requires root'
for tool in /usr/bin/dscl /usr/sbin/sysadminctl /usr/sbin/dseditgroup /usr/bin/dscacheutil /usr/bin/id /usr/bin/stat /usr/bin/install /bin/ls; do
    [ -x "$tool" ] || fail "required system tool unavailable: $tool"
done
# A resumed --keyholder-only run finds the keyholder it created: nothing is
# created again, the account is re-verified and its directories re-applied.
keyholder_resume=false
if [ "$keyholder_only" = true ] && /usr/bin/dscl . -read "/Users/$keyholder_user" UniqueID >/dev/null 2>&1; then
    keyholder_resume=true
    new_names='' new_uids='' new_gids=''
fi
# Query the search node as well as the local directory: fail closed on directory errors.
users=$(/usr/bin/dscl /Search -list /Users UniqueID) || fail 'cannot enumerate users'
groups=$(/usr/bin/dscl /Search -list /Groups PrimaryGroupID) || fail 'cannot enumerate groups'
local_users=$(/usr/bin/dscl . -list /Users UniqueID) || fail 'cannot enumerate local users'
local_groups=$(/usr/bin/dscl . -list /Groups PrimaryGroupID) || fail 'cannot enumerate local groups'
check_records() {
    local records=$1 name id extra ids=$new_gids
    [ "$2" = group ] || ids=$new_uids
    while read -r name id extra; do
        [ -n "$name" ] || continue
        if [ -n "$extra" ] || ! [[ "$id" =~ ^-?[0-9]+$ ]]; then
            fail 'ambiguous directory record; review manually'
        fi
        case " $new_names " in *" $name "*) fail "account/group name collision: $name" ;; esac
        case " $ids " in *" $id "*) fail "numeric $2 collision: $id" ;; esac
    done <<< "$records"
}
check_records "$users" user; check_records "$local_users" user
check_records "$groups" group; check_records "$local_groups" group
# Reject dangling supplementary memberships before creating any name.
for node in /Search .; do
    memberships=$(/usr/bin/dscl "$node" -list /Groups GroupMembership) || fail 'cannot enumerate supplementary group membership'
    while read -r group members; do
        for member in $members; do
            case " $new_names " in *" $member "*) fail "preexisting supplementary membership in $group" ;; esac
        done
    done <<< "$memberships"
done
# dscacheutil catches aliases/search-policy records not represented by canonical names.
for name in $new_names; do
    cached=$(/usr/bin/dscacheutil -q user -a name "$name") || fail 'cannot query cached users'
    [ -z "$cached" ] || fail "cached user collision: $name"
    cached=$(/usr/bin/dscacheutil -q group -a name "$name") || fail 'cannot query cached groups'
    [ -z "$cached" ] || fail "cached group collision: $name"
done
[ "$(/usr/bin/id -u "$owner_user")" = "$owner_uid" ] || fail 'owner identity mismatch'
owner_groups=$(/usr/bin/id -G "$owner_user") || fail 'cannot resolve owner groups'
for gid in $owner_groups; do
    case " $new_gids " in *" $gid "*) fail 'primary group shared with owner' ;; esac
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
    case " $new_gids " in *" $gid "*) fail 'proposed primary group referenced by existing user' ;; esac
done <<< "$primary_groups"
check_parent() {
    local path=$1 mode acl first entry
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
}
if [ "$signer_only" = true ] || [ "$keyholder_only" = true ]; then
    # The existing installation and its named accounts are the reviewed ones.
    for path in /Library "$prefix" "$prefix/var"; do check_parent "$path"; done
    [ "$(/usr/bin/id -u "$controller_user")" = "$controller_uid" ] || fail 'controller identity mismatch'
    [ "$(/usr/bin/id -g "$controller_user")" = "$controller_gid" ] || fail 'controller primary group mismatch'
    [ "$(/usr/bin/id -u "$job_user")" = "$job_uid" ] || fail 'job identity mismatch'
    [ "$(/usr/bin/id -g "$job_user")" = "$job_gid" ] || fail 'job primary group mismatch'
    targets=''
else
    for path in /Library /Users; do check_parent "$path"; done
    targets="$prefix $home"
fi
if [ "$signer" = true ]; then
    targets="$targets $prefix/signer-profiles $prefix/var/signer $prefix/var/signer-run $prefix/var/signer-inbox"
fi
if [ "$keyholder" = true ] && [ "$keyholder_resume" = false ]; then
    targets="$targets $prefix/var/keyholder $prefix/var/keyholder-run"
fi
for path in $targets; do
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
if [ "$signer_only" = false ] && [ "$keyholder_only" = false ]; then
    create_accounts
    validate_created_accounts
    /usr/bin/install -d -o root -g wheel -m 0755 "$prefix" "$prefix/bin" "$prefix/health"
    /usr/bin/install -d -o root -g wheel -m 0755 "$prefix/config"
    /usr/bin/install -d -o root -g wheel -m 0711 "$prefix/var" "$prefix/var/workspaces"
    /usr/bin/install -d -o "$controller_uid" -g "$controller_gid" -m 0700 "$prefix/var/controller" "$prefix/var/controller/secrets" "$prefix/var/controller/run" "$prefix/var/controller/log"
    /usr/bin/install -d -o root -g wheel -m 0700 "$prefix/var/broker" "$prefix/var/broker/log" "$prefix/var/exports"
    /usr/bin/install -d -o "$job_uid" -g "$job_gid" -m 0700 "$home"
    printf '%s\n' 'Created accounts and empty protected directories only. Controller password remains disabled; the job password was entered interactively during sysadminctl creation. Verified dedicated primary groups, no prohibited supplementary groups, and no job IsHidden attribute.'
fi
if [ "$signer" = true ]; then
    create_signer
    validate_signer_accounts
    provision_signer_directories
    printf '%s\n' "Created hidden nonlogin $signer_user, its group and $signrpc_group (members $controller_user and $signer_user only) and empty signer directories. Verified the job account belongs to neither group."
fi
if [ "$keyholder" = true ]; then
    if [ "$keyholder_resume" = false ]; then
        create_keyholder
    fi
    validate_keyholder_accounts
    provision_keyholder_directories
    printf '%s\n' "Verified hidden nonlogin $keyholder_user, its group and $keyrpc_group (members $controller_user and $keyholder_user only) and the keyholder directories. Verified the job account belongs to neither group."
fi
printf '%s\n' 'Install reviewed inputs separately and qualify before enabling anything.'
}
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
