#!/usr/bin/env python3
"""Public synthetic native-byte corpus producer; run only after disclosure/admission.

Requires an unprivileged Darwin caller, public native helpers and a saved receipt
from the admitted reviewed build. Both executables must match that receipt;
the native fixture source must also match prepare.py's source-only receipt.
Only the narrow root protocol enters sudo; Python and the profile oracle remain
unprivileged. Never installs, runs recipes or reads host config. Build receipts
record provenance and custody, not independent authorization or runtime approval.

Evidence is exact native writing/verifying and real filesystem refusal, NOT
Collect, host isolation, tool execution, or installed-runtime evidence.
Requests/responses are capped at 4 MiB, stderr at 64 KiB, each invocation at 120s,
and the complete corpus at 32 MiB. No partial output is published on failure.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time


sys.path.insert(0, str(Path(__file__).resolve().parent))
from root_protocol import RootProtocol
NATIVE_SHA = '9440aedf29fa10b9fb879f018cdd034162c20527732176e999d239d566647ba2'
IO_LIMIT = 4 << 20
ERR_LIMIT = 64 << 10
CORPUS_LIMIT = 32 << 20
PREVIOUS = '/Library/macserve/var/qualification/public-fixture-r1'
CURRENT = '/Library/macserve/var/qualification/public-fixture-r2'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def b64(raw):
    return base64.b64encode(raw).decode('ascii')


def unbase64(value):
    require(isinstance(value, str), 'expected base64 text')
    raw = base64.b64decode(value, validate=True)
    require(b64(raw) == value, 'noncanonical base64')
    return raw


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=no_duplicates,
                      parse_constant=lambda value: require(False, 'nonfinite JSON'))


def read_small(path, limit):
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, 'input exceeds size limit')
    return raw


def file_sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()



def invoke(binary, raw, environment):
    require(len(raw) <= IO_LIMIT, 'native request exceeds limit')
    if isinstance(binary, RootProtocol):
        return binary.invoke(raw)
    proc = subprocess.Popen([str(binary)], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=environment, cwd=environment['HOME'])
    output = bytearray()
    errors = bytearray()
    sent = 0
    deadline = time.monotonic() + 120
    try:
        with selectors.DefaultSelector() as poll:
            for stream, event in ((proc.stdin, selectors.EVENT_WRITE),
                                  (proc.stdout, selectors.EVENT_READ),
                                  (proc.stderr, selectors.EVENT_READ)):
                os.set_blocking(stream.fileno(), False)
                poll.register(stream, event)
            while poll.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, 'native invocation timed out')
                for key, _ in poll.select(min(remaining, 1)):
                    stream = key.fileobj
                    if stream is proc.stdin:
                        try:
                            sent += os.write(stream.fileno(), raw[sent:sent + 65536])
                        except BrokenPipeError:
                            sent = len(raw)
                        if sent == len(raw):
                            poll.unregister(stream)
                            stream.close()
                    else:
                        chunk = os.read(stream.fileno(), 65536)
                        if not chunk:
                            poll.unregister(stream)
                            stream.close()
                            continue
                        buffer = output if stream is proc.stdout else errors
                        buffer.extend(chunk)
                        require(len(buffer) <= (IO_LIMIT if stream is proc.stdout else ERR_LIMIT),
                                'native output exceeds limit')
        status = proc.wait(timeout=max(0.01, deadline - time.monotonic()))
        return status, bytes(output), bytes(errors)
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            stream.close()


def native_response(result, files=False):
    status, out, err = result
    require(status == 0, 'native operation failed: ' + err.decode('utf-8', errors='replace'))
    response = decode(out)
    require(isinstance(response, dict) and response.get('native_verified') is True,
            'native verifier success missing')
    require(set(response) == ({'native_verified', 'files'} if files else {'native_verified'}),
            'unexpected native response fields')
    if files:
        bundle = response['files']
        require(isinstance(bundle, dict) and 0 < len(bundle) <= 128, 'invalid bundle count')
        require({'candidate.json', 'challenge.json', 'before.json', 'boundary-evidence.json',
                 'qualification.json'} <= set(bundle), 'incomplete native bundle')
        for name, value in bundle.items():
            require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,239}', name) is not None,
                    'unsafe native basename')
            unbase64(value)
    return response


def stamp(value):
    return value.isoformat().replace('+00:00', 'Z')


def profile_config(populated):
    return {'profiles': [
        {'id': name, 'version': 1, 'repo': 'example/' + name, 'kind': 'build',
         'xcode': {'version': '16.0', 'build': '16A242d'},
         'developer_dir': '/Applications/Xcode.app/Contents/Developer',
         'work_dir': '.', 'run': {'executable': '/usr/bin/true', 'args': []}}
        for name in (('fixture-one', 'fixture-two') if populated else ())]}


def make_case(name, now, generator, oracle, environment, controls):
    populated = name == 'populated'
    profiles_raw = encoded(profile_config(populated))
    status, out, err = invoke(oracle, profiles_raw, environment)
    require(status == 0, 'native profile oracle failed: ' + err.decode('utf-8', errors='replace'))
    snapshot = decode(out)
    require(isinstance(snapshot, dict) and set(snapshot) == {'profiles', 'digests'},
            'invalid native snapshot shape')
    models, digests = snapshot['profiles'], snapshot['digests']
    require(isinstance(models, list) and isinstance(digests, dict), 'nonnull native snapshot required')
    expected = {'fixture-one', 'fixture-two'} if populated else set()
    require(len(models) == len(expected) and {p['id'] for p in models} == expected
            and set(digests) == expected, 'unexpected native profile identities')
    require(all(isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v) for v in digests.values()),
            'invalid native profile digest')
    deployment = b'public synthetic deployment\n'
    sources = b'public synthetic source pins\n'
    accepted = encoded({})
    baseline = encoded({'persistence_sha256': sha(accepted)})
    attestation = encoded({})
    case = {'now': stamp(now), 'previous_session': PREVIOUS, 'current_session': CURRENT,
            'profiles_raw': b64(profiles_raw), 'native_snapshot': snapshot,
            'env': b64(deployment), 'sources': b64(sources), 'baseline': b64(baseline),
            'accepted': b64(accepted), 'attestation': b64(attestation)}
    for current in (False, True):
        round_name = 'current' if current else 'previous'
        created = now - dt.timedelta(hours=12 if current else 18)
        observation = {'job_uid': 6202, 'boot': ('b' if current else 'a') * 64,
                       'baseline_sha256': sha(baseline), 'profiles': digests,
                       'identity_valid': True, 'baseline_valid': True, 'console_admissible': True,
                       'persistence': {'valid': True, 'needs_review': False, 'last_verified': stamp(created)}}
        challenge = {'schema': 4, 'id': sha((name + '/' + round_name).encode()),
                     'created': stamp(created), 'expires': stamp(created + dt.timedelta(hours=2)),
                     'environment': {'JobUID': 6202}, 'observation': observation,
                     'boot_session': ('22222222-3333-4444-5555-666666666666' if current else
                                      '11111111-2222-3333-4444-555555555555'),
                     'environment_sha256': sha(deployment), 'tcp': ['localhost:1'],
                     'udp': [], 'allow': [], 'profiles': models}
        if populated:
            challenge['sources_sha256'] = sha(sources)
        if current:
            challenge.update(previous=PREVIOUS,
                             previous_sha256=sha(unbase64(case['previous']['files']['candidate.json'])))
        case[round_name] = native_response(invoke(generator, encoded(
            {'mode': 'generate', 'challenge': challenge, 'current': current}), environment), files=True)
        bundle = case[round_name]['files']
        bundle_hash = sha(encoded(bundle))
        # Positive re-verification precedes every negative control for this bundle.
        for kind in ('positive', 'raw-artifact', 'noncanonical-framing', 'mode', 'owner', 'acl', 'symlink'):
            request = {'mode': 'verify', 'files': bundle}
            extra = {}
            if kind == 'raw-artifact':
                target = 'before.json'
                original = unbase64(bundle[target])
                changed = original + b'\n'
                request['files'] = dict(bundle, **{target: b64(changed)})
                extra = {'target': target, 'original_sha256': sha(original),
                         'tampered_sha256': sha(changed)}
            elif kind == 'noncanonical-framing':
                category = 'unix_socket_boundary'
                target = 'category-' + category + '.json'
                original = unbase64(bundle[target])
                changed = original + b'\n'
                candidate = decode(unbase64(bundle['candidate.json']))
                boundary = decode(unbase64(bundle['boundary-evidence.json']))
                qualification = decode(unbase64(bundle['qualification.json']))
                candidate['artifacts'][target] = sha(changed)
                candidate['categories'][category]['probe']['artifact_sha256'] = sha(changed)
                matching = [probe for probe in boundary['probes'] if probe['category'] == category]
                require(len(matching) == 1, 'expected exactly one matching native boundary probe')
                matching[0]['artifact_sha256'] = sha(changed)
                boundary_raw = encoded(boundary)
                qualification['boundary_evidence_sha256'] = sha(boundary_raw)
                hostile = dict(bundle)
                hostile[target] = b64(changed)
                hostile['candidate.json'] = b64(encoded(candidate))
                hostile['boundary-evidence.json'] = b64(boundary_raw)
                hostile['qualification.json'] = b64(encoded(qualification))
                request['files'] = hostile
                extra = {'target': target, 'original_sha256': sha(original),
                         'tampered_sha256': sha(changed)}
            elif kind != 'positive':
                request['tamper_protection'] = kind
            raw_request = encoded(request)
            result = invoke(generator, raw_request, environment)
            code, stdout, stderr = result
            text = stderr.decode('utf-8', errors='strict')
            if kind == 'positive':
                native_response(result)
            else:
                require(code > 0 and bool(stderr), 'negative control did not refuse normally')
                if kind not in ('raw-artifact', 'noncanonical-framing'):
                    require('tamper_protection ' + kind + ' refused: ' in text,
                            'missing real protection-mutation refusal marker')
            controls.append({'case': name, 'round': round_name, 'kind': kind,
                             'exit_code': code, 'stderr': text, 'request_sha256': sha(raw_request),
                             'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr),
                             'bundle_sha256': bundle_hash, **extra})
    return case


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--generator', required=True, type=Path)
    parser.add_argument('--oracle', required=True, type=Path)
    parser.add_argument('--source-receipt', required=True, type=Path)
    parser.add_argument('--build-receipt', required=True, type=Path)
    parser.add_argument('--build-receipt-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    require(sys.platform == 'darwin' and os.getuid() != 0 and os.geteuid() != 0,
            'unprivileged Darwin caller required')
    fixture = Path(__file__).absolute().with_name('history_fixture_test.go.source')
    fixture_hash = sha(read_small(fixture, 1 << 20))
    receipt = decode(read_small(args.source_receipt, 64 << 10))
    require(receipt == {'native_archive_sha256': NATIVE_SHA,
                        'fixture_source_sha256': fixture_hash,
                        'build_executed': False, 'native_execution': False},
            'source receipt must exactly match archive and fixture source')
    require(args.output.is_absolute() and not os.path.lexists(args.output),
            'exclusive absolute output required')
    generator_hash, oracle_hash = file_sha(args.generator), file_sha(args.oracle)
    build_raw = read_small(args.build_receipt, 1 << 20)
    require(re.fullmatch('[0-9a-f]{64}', args.build_receipt_sha256) is not None and
            sha(build_raw) == args.build_receipt_sha256, 'build receipt identity differs')
    build = decode(build_raw)
    require(build['schema'] == 1 and build['independent_runtime_approval'] is False and
            build['native_archive_sha256'] == NATIVE_SHA and
            build['fixture_source_sha256'] == fixture_hash and
            build['build_outputs'] == {
                'native-history-fixture': generator_hash,
                'native-profile-oracle': oracle_hash,
                'history-fixture-source.json': file_sha(args.source_receipt)},
            'native inputs differ from the admitted build receipt')
    require(all(re.fullmatch('[0-9a-f]{40}', build[name]) is not None
                for name in ('source_head', 'workflow_head')) and
            re.fullmatch('[0-9a-f]{64}', build['manifest_sha256']) is not None,
            'build source identity missing')
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                   'HOME': str(args.output.parent)}
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    controls = []
    corpus = {'schema': 1, 'native_source_sha256': NATIVE_SHA,
              'fixture_source_sha256': fixture_hash, 'generator_sha256': generator_hash,
              'oracle_sha256': oracle_hash, 'generated_at': stamp(now), 'cases': {},
              'controls': controls}
    corpus['build_receipt_sha256'] = args.build_receipt_sha256
    corpus['source_head'] = build['source_head']
    corpus['workflow_head'] = build['workflow_head']
    corpus['source_manifest_sha256'] = build['manifest_sha256']
    broker = RootProtocol(args.generator, build['build_outputs']['native-history-fixture'])
    try:
        for name in ('empty', 'populated'):
            corpus['cases'][name] = make_case(name, now, broker, args.oracle, environment, controls)
        require(len(controls) == 28, 'incomplete original controls')
        require(file_sha(args.generator) == generator_hash and file_sha(args.oracle) == oracle_hash,
                'unprivileged native executable changed')
        raw = encoded(corpus)
        require(len(raw) <= CORPUS_LIMIT, 'complete corpus exceeds limit')
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        require(read_small(args.output, CORPUS_LIMIT) == raw, 'durable corpus readback differs')
        parent_fd = os.open(args.output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        # Root sees only stdout requests and this digest ACK; it never opens,
        # copies to, traverses or chowns the runner-owned output directory.
        custody = broker.acknowledge(sha(raw))
        custody_path = args.output.with_name('root-protocol.json')
        fd = os.open(custody_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(encoded(custody))
            output.flush()
            os.fsync(output.fileno())
    finally:
        broker.close()
    print(json.dumps({'output_sha256': sha(raw), 'bytes': len(raw), 'schema': 1,
                      'cases': 2, 'native_rounds': 4, 'positive_controls': 4,
                      'refusal_controls': 24, 'scope': 'synthetic native bytes/protection only'},
                     sort_keys=True))


if __name__ == '__main__':
    def deadline_expired(signum, frame):
        raise TimeoutError('600-second corpus command deadline exceeded')
    signal.signal(signal.SIGALRM, deadline_expired)
    signal.alarm(600)
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print('public native corpus refused: ' + str(error), file=sys.stderr)
        sys.exit(1)
    finally:
        signal.alarm(0)
