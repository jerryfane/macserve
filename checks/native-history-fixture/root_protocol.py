"""Unprivileged fixed native protocol; no Python file is ever run by root.

The literal bootstrap is an argument to trusted /bin/sh, never a checkout shell
file or stdin script. Stdin contains ONLY helper bytes and bounded JSON data.
The helper digest comes from the admitted reviewed build's saved receipt, captured
before privilege entry. It is a custody pin, not independent runtime approval.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

# Fixed trusted system tools only. No eval, source, runner paths, command tokens,
# inherited imports, user startup files, trap cleanup, or runner-owned parents.
BOOTSTRAP = r'''set -efu
umask 077
[ "$#" -eq 2 ] || exit 1
expected=$1
size=$2
case "$expected" in *[!0123456789abcdef]*|'') exit 1;; esac
[ "${#expected}" -eq 64 ] || exit 1
case "$size" in *[!0123456789]*|'') exit 1;; esac
[ "${#size}" -le 8 ] && [ "$size" -gt 0 ] && [ "$size" -le 67108864 ] || exit 1
[ "$(/usr/bin/id -u)" = 0 ] || exit 1
for parent in / /private /private/var /private/var/root; do
    [ -d "$parent" ] && [ ! -L "$parent" ] || exit 1
    [ "$(/usr/bin/stat -f %u "$parent")" = 0 ] || exit 1
    mode=$(/usr/bin/stat -f %Lp "$parent")
    case "$mode" in *[!01234567]*|'') exit 1;; esac
    [ "$((0$mode & 022))" -eq 0 ] || exit 1
    acl=$(/bin/ls -lde "$parent")
    case "$acl" in *'
'*) exit 1;; esac
done
root=$(/usr/bin/mktemp -d /private/var/root/native-contract.XXXXXXXX) || exit 1
cd "$root"
[ "$(/usr/bin/stat -f %u:%Lp .)" = 0:700 ] || exit 1
/bin/dd bs=1 count="$size" of=native 2>/dev/null
[ "$(/usr/bin/stat -f %z native)" = "$size" ] || exit 1
/bin/chmod 0500 native
[ "$(/usr/bin/stat -f %u:%Lp:%l native)" = 0:500:1 ] || exit 1
acl=$(/bin/ls -lde native)
case "$acl" in *'
'*) exit 1;; esac
actual=$(OPENSSL_CONF=/dev/null /usr/bin/openssl dgst -sha256 native)
[ "${actual##* }" = "$expected" ] || exit 1
MACSERVE_NATIVE_BROKER=1 MACSERVE_NATIVE_BUILD_SHA256="$expected" ./native
# Only success following the explicit durable-custody ACK reaches deletion.
cd /private/var/root
/bin/rm -rf "$root"
[ ! -e "$root" ] || exit 1
printf '%s\n' '{"root_scratch_removed":true}'
'''


class RootProtocol:
    def __init__(self, helper, build_sha256):
        if os.getuid() == 0 or os.geteuid() == 0:
            raise RuntimeError('protocol client must be unprivileged')
        if re.fullmatch('[0-9a-f]{64}', build_sha256) is None:
            raise RuntimeError('build receipt compiled digest required')
        with Path(helper).open('rb') as stream:
            raw = stream.read((64 << 20) + 1)
        if not raw or len(raw) > 64 << 20 or hashlib.sha256(raw).hexdigest() != build_sha256:
            raise RuntimeError('compiled helper differs from build receipt')
        self.proc = subprocess.Popen(
            ['/usr/bin/sudo', '-n', '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin',
             'HOME=/private/var/root', 'LANG=C', 'LC_ALL=C', '/bin/sh', '-c',
             BOOTSTRAP, 'native-bootstrap', build_sha256, str(len(raw))],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}, cwd='/')
        self.transcript = hashlib.sha256()
        self.proc.stdin.write(raw)
        self.proc.stdin.flush()
        ready = self.receive()
        expected = {'ready': True, 'helper_sha256': build_sha256,
                    'uid': 0, 'euid': 0, 'pgid': os.getpgrp(), 'session': os.getsid(0), 'helper_mode': '0500',
                    'helper_links': 1, 'protected_scratch': True}
        if (not isinstance(ready, dict) or
                set(ready) != set(expected) | {'helper_device', 'helper_inode'} or
                any(ready.get(key) != value for key, value in expected.items()) or
                any(type(ready[key]) is not int or ready[key] < 0
                    for key in ('helper_device', 'helper_inode'))):
            self.close()
            raise RuntimeError('root identity or inherited process group mismatch')
        self.ready = ready

    def receive(self):
        raw = self.proc.stdout.readline((6 << 20) + 1)
        if not raw.endswith(b'\n') or len(raw) > 6 << 20:
            raise RuntimeError('root protocol frame limit or EOF')
        self.last_frame = raw
        return json.loads(raw)

    def send(self, value):
        raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
        if len(raw) > 6 << 20:
            raise RuntimeError('root protocol request limit')
        self.proc.stdin.write(raw)
        self.proc.stdin.flush()
        return raw

    def invoke(self, raw):
        if not raw or len(raw) > 4 << 20:
            raise RuntimeError('native input limit')
        request = self.send({'operation': 'native', 'request': base64.b64encode(raw).decode('ascii')})
        reply = self.receive()
        if set(reply) != {'status', 'stdout', 'stderr'} or type(reply['status']) is not int or reply['status'] not in (0, 1):
            raise RuntimeError('native response shape')
        out = base64.b64decode(reply['stdout'] or '', validate=True)
        err = base64.b64decode(reply['stderr'] or '', validate=True)
        if len(out) > 4 << 20 or len(err) > 64 << 10:
            raise RuntimeError('native response limit')
        self.transcript.update(request)
        self.transcript.update(self.last_frame)
        return reply['status'], out, err

    def acknowledge(self, corpus_sha256):
        transcript = self.transcript.hexdigest()
        self.send({'operation': 'ack', 'transcript': transcript, 'corpus': corpus_sha256})
        if self.receive() != {'acknowledged': True, 'transcript': transcript, 'corpus': corpus_sha256}:
            raise RuntimeError('root acknowledgement mismatch')
        self.proc.stdin.close()
        if self.receive() != {'root_scratch_removed': True} or self.proc.wait(timeout=30) != 0:
            raise RuntimeError('root cleanup receipt missing')
        self.proc.stdout.close()
        return {**self.ready, 'transcript_sha256': transcript, 'corpus_sha256': corpus_sha256,
                'unprivileged_durable_readback_ack': True, 'root_scratch_removed': True}

    def close(self):
        # Unprivileged Python cannot promise to signal root or escaped descendants.
        # Closing stdin requests fail-closed broker exit; no ACK means retain scratch.
        if not self.proc.stdin.closed:
            self.proc.stdin.close()
        self.proc.stdout.close()
