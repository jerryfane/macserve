#!/usr/bin/env python3
"""Reviewed public-only hosted runner orchestration; never an installed-service test.

All native production files come from the SHA-pinned public archive. Root work is
confined to one exclusive directory and fixed tools. No private inputs accepted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.request

ARCHIVE_SHA = '9440aedf29fa10b9fb879f018cdd034162c20527732176e999d239d566647ba2'
ARCHIVE_URL = 'https://codeload.github.com/jerryfane/macserve/tar.gz/refs/tags/v0.1.16'
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PYTHON = [sys.executable, '-I', '-S', '-B']
EXPORT_NAMES = {'build-provenance.json', 'public-corpus.json', 'provenance.json', 'command-receipts.json', 'SHA256SUMS'}
TOOLS = ['checks/native-history-fixture/public_contract.py',
         'checks/native-history-fixture/root_protocol.py',
         'checks/native-history-fixture/history_fixture_test.go.source']
SUPERVISION_POLICY = 'cooperative-hosted-vm-v1'

PUBLIC_STAGES = frozenset({
    'go-version', 'runner-memory', 'download-archive', 'prepare-source',
    'download-modules', 'verify-modules', 'compile-history', 'compile-oracle',
    'native-corpus',
})
PUBLIC_FAILURE_CODES = frozenset({
    'child_group_leftovers', 'cleanup_deadline_exceeded', 'cleanup_failure',
    'cleanup_verification_failure', 'command_exit_nonzero', 'command_not_started',
    'deadline_exceeded', 'descendant_escaped_owned_group', 'group_signal_failure',
    'group_verification_failure', 'interrupted', 'invalid_arguments',
    'invalid_budget', 'invalid_command', 'invalid_label', 'invalid_new_log_directory',
    'invalid_ps_leader', 'invalid_ps_snapshot', 'leader_reap_failure',
    'log_sync_failure', 'missing_command_separator', 'monitor_failure',
    'noncanonical_output_path', 'output_drain_timeout', 'output_write_failure',
    'owned_group_not_verified_gone', 'owned_group_remains', 'pipe_close_failure',
    'ps_cleanup_failure', 'ps_deadline_exceeded', 'ps_failed',
    'ps_output_limit_exceeded', 'receipt_unavailable', 'rss_budget_exceeded',
    'rss_unmeasured', 'sampling_gap_exceeded', 'setup_failure',
    'stdout_limit_exceeded', 'stderr_limit_exceeded', 'unsupported_python_version',
})


def public_failure(work, label, monitor_exit):
    """Project an untrusted receipt onto fixed codes and bounded exit integers."""
    summary = {'stage': label if label in PUBLIC_STAGES else 'unknown',
               'monitor_exit': monitor_exit, 'command_exit': None,
               'reasons': ['receipt_unavailable']}
    if label not in PUBLIC_STAGES:
        return summary
    try:
        path = work / (label + '.json')
        regular(path)
        receipt = json.loads(small(path, 128 << 10))
        require(receipt['schema'] == 'native-budget-monitor/v1' and
                receipt['label'] == label, 'receipt binding differs')
        failures = receipt['failures']
        require(isinstance(failures, list) and len(failures) <= 64 and
                all(isinstance(code, str) for code in failures), 'invalid failure codes')
        reasons = sorted({code for code in failures if code in PUBLIC_FAILURE_CODES})
        if not failures or any(code not in PUBLIC_FAILURE_CODES for code in failures):
            reasons.append('unclassified_failure')
        summary['reasons'] = reasons
        exit_code = receipt.get('command_exit_code')
        if type(exit_code) is int and -255 <= exit_code <= 255:
            summary['command_exit'] = exit_code
    except Exception:
        # Never serialize exception text, argv, paths, environment or stream data.
        pass
    return summary

def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def small(path, limit):
    with path.open('rb') as source:
        data = source.read(limit + 1)
    require(len(data) <= limit, 'file exceeds explicit bound')
    return data


def new_bytes(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    require(small(path, len(data)) == data, 'new file read-back differs')


def new_json(path, value):
    new_bytes(path, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())


def regular(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'regular unlinked input required')


def copy_exact(source, target, mode=0o600, limit=128 << 20):
    regular(source)
    raw = small(source, limit)
    new_bytes(target, raw, mode)
    require(digest(source) == digest(target), 'copied file changed or differs')


def source_manifest(repo, expected):
    require(re.fullmatch('[0-9a-f]{64}', expected) is not None, 'checkout manifest digest required')
    manifest = repo / 'PUBLIC-SOURCE-MANIFEST.json'
    require(digest(manifest) == expected, 'source manifest changed from initial checkout digest')
    value = json.loads(small(manifest, 1 << 20))
    require(value['schema'] == 1 and value['native_archive_sha256'] == ARCHIVE_SHA,
            'wrong source manifest contract')
    names = set()
    for row in value['files']:
        relative = row['path']
        path = Path(relative)
        require(not path.is_absolute() and '..' not in path.parts and relative not in names,
                'unsafe source allowlist')
        names.add(relative)
        regular(repo / path)
        require((repo / path).stat().st_size == row['bytes'] and digest(repo / path) == row['sha256'],
                'reviewed source bytes differ')
    require(set(TOOLS) | {'PUBLIC-SOURCE-ALLOWLIST.txt',
                         'checks/native-history-fixture/prepare.py',
                         'checks/native-history-fixture/ci.py',
                         'checks/native-history-fixture/budget.py',
                         'checks/native-profile-oracle/main.go'} <= names, 'required source missing')
    allowlist = small(repo / 'PUBLIC-SOURCE-ALLOWLIST.txt', 64 << 10).decode('ascii').splitlines()
    require(len(allowlist) == len(set(allowlist)) and
            set(allowlist) == names | {'PUBLIC-SOURCE-MANIFEST.json'},
            'exact public packet allowlist differs')
    return value


def environment(work, go):
    # Public proxy only, no direct/VCS fallback, no inherited credentials or config.
    return {'PATH': str(go.parent) + ':/usr/bin:/bin:/usr/sbin:/sbin',
            'HOME': str(work / 'home'), 'TMPDIR': str(work / 'tmp'), 'LANG': 'C', 'LC_ALL': 'C',
            'GOTOOLCHAIN': 'local', 'GOMAXPROCS': '2', 'GOMEMLIMIT': '768MiB',
            'GOPATH': str(work / 'gopath'), 'GOCACHE': str(work / 'go-cache'),
            'GOMODCACHE': str(work / 'go-mod-cache'), 'GOPROXY': 'off', 'GOSUMDB': 'off',
            'GOPRIVATE': '', 'GONOPROXY': '', 'GONOSUMDB': '',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
            'GIT_TERMINAL_PROMPT': '0', 'CGO_ENABLED': '0'}


def step(work, label, seconds, rss, command, env, cwd):
    monitor = [*PYTHON, str(HERE / 'budget.py'), '--label', label,
               '--seconds', str(seconds), '--rss-mib', str(rss),
               '--log-dir', str(work / (label + '-logs')),
               '--receipt', str(work / (label + '.json'))]
    if label in ('go-version', 'runner-memory'):
        monitor.append('--allow-unmeasured')
    if label in ('download-modules', 'verify-modules', 'compile-history', 'compile-oracle'):
        command = ['/usr/bin/nice', '-n', '10', *command]
    monitor.extend(['--', *map(str, command)])
    # Cooperative sampled monitor only; privileged survivors/escapes rely on the
    # separately admitted disposable hosted-VM job deadline boundary.
    result = subprocess.run(monitor, cwd=cwd, env=env, check=False)
    if result.returncode != 0:
        print(json.dumps(public_failure(work, label, result.returncode), sort_keys=True),
              file=sys.stderr)
    require(result.returncode == 0, 'bounded command failed: ' + label)
    receipt = json.loads(small(work / (label + '.json'), 128 << 10))
    return receipt


def download(destination):
    require(not destination.exists(), 'archive output exists')
    with urllib.request.urlopen(ARCHIVE_URL, timeout=30) as response:
        require(response.url.startswith('https://codeload.github.com/'), 'unexpected download host')
        raw = response.read((64 << 20) + 1)
    require(len(raw) <= 64 << 20 and hashlib.sha256(raw).hexdigest() == ARCHIVE_SHA,
            'public archive SHA256 mismatch')
    new_bytes(destination, raw)
    print(json.dumps({'native_archive_sha256': ARCHIVE_SHA, 'bytes': len(raw)}))


def run(args):
    require(sys.platform == 'darwin' and sys.version_info >= (3, 11), 'Darwin and Python >=3.11 required')
    require(os.getuid() != 0, 'build orchestrator must use the hosted runner account')
    require(re.fullmatch('[0-9]+', args.run_id) and re.fullmatch('[0-9]+', args.attempt), 'numeric run identity required')
    require(re.fullmatch('[0-9a-f]{40}', args.head), 'exact source commit required')
    require(re.fullmatch('[0-9a-f]{40}', args.workflow_head), 'exact executing workflow commit required')
    started = time.monotonic()
    manifest = source_manifest(REPO, args.manifest_sha256)
    require(not args.work.exists(), 'work must be exclusive')
    args.work.mkdir(mode=0o700)
    work = args.work.resolve()
    for name in ('home', 'tmp', 'gopath', 'go-cache', 'go-mod-cache', 'stage'):
        (work / name).mkdir(mode=0o700)
    env = environment(work, args.go.resolve(strict=True))
    receipts = []
    toolchain_hashes = {'go_executable_sha256': digest(args.go),
                        'python_executable_sha256': digest(Path(sys.executable))}
    receipts.append(step(work, 'runner-memory', 15, 256,
                         ['/usr/sbin/sysctl', '-n', 'hw.memsize'], env, work))
    memory_bytes = int(small(work / 'runner-memory-logs/runner-memory.stdout.log', 4096))
    require(memory_bytes >= 6 << 30, 'hosted runner has less than 6 GiB physical RAM')
    free_disk = shutil.disk_usage(work).free
    require(free_disk >= 8 << 30, 'hosted runner has less than 8 GiB free scratch')
    receipts.append(step(work, 'go-version', 15, 256, [args.go, 'version'], env, work))
    version = small(work / 'go-version-logs/go-version.stdout.log', 4096).decode().strip()
    require(version.startswith('go version go1.26.4 darwin/'), 'Go 1.26.4 Darwin toolchain required')
    receipts.append(step(work, 'download-archive', 90, 256,
                         [*PYTHON, __file__, 'download', str(work / 'source.tar.gz')], env, work))
    native = work / 'native'
    receipts.append(step(work, 'prepare-source', 60, 256,
                         [*PYTHON, HERE / 'prepare.py', '--archive', work / 'source.tar.gz', native], env, work))
    oracle = native / 'cmd/profile-oracle'; oracle.mkdir(mode=0o700)
    copy_exact(REPO / 'checks/native-profile-oracle/main.go', oracle / 'main.go')
    module_hashes = {name: digest(native / name) for name in ('go.mod', 'go.sum')}
    require(module_hashes == manifest['native_module_sha256'], 'reviewed module pins differ')
    online = dict(env, GOPROXY='https://proxy.golang.org', GOSUMDB='sum.golang.org')
    receipts.append(step(work, 'download-modules', 300, 1536,
                         [args.go, 'mod', 'download'], online, native))
    receipts.append(step(work, 'verify-modules', 120, 1536,
                         [args.go, 'mod', 'verify'], env, native))
    stage = work / 'stage'
    receipts.append(step(work, 'compile-history', 600, 3072,
                         [args.go, 'test', '-c', '-p=1', '-mod=readonly', '-trimpath', '-buildvcs=false',
                          '-o', stage / 'native-history-fixture', './internal/qualification'], env, native))
    receipts.append(step(work, 'compile-oracle', 180, 1536,
                         [args.go, 'build', '-p=1', '-mod=readonly', '-trimpath', '-buildvcs=false',
                          '-o', stage / 'native-profile-oracle', './cmd/profile-oracle'], env, native))
    require(module_hashes == {name: digest(native / name) for name in module_hashes}, 'module pins changed')
    copy_exact(native / 'history-fixture-source.json', stage / 'history-fixture-source.json')
    stage_files = {path.name: digest(path) for path in stage.iterdir()}
    # The admitted reviewed build creates this receipt BEFORE privileged work.
    # It is source-to-binary provenance, not independent runtime approval.
    source_manifest(REPO, args.manifest_sha256)
    require(toolchain_hashes == {'go_executable_sha256': digest(args.go),
                                 'python_executable_sha256': digest(Path(sys.executable))},
            'toolchain executable changed during build')
    build_receipt = stage / 'build-provenance.json'
    new_json(build_receipt,
             {'schema': 1, 'scope': 'source-to-binary build receipt; not independent approval',
              'source_head': args.head, 'workflow_head': args.workflow_head,
              'manifest_sha256': args.manifest_sha256,
              'run_id': args.run_id, 'run_attempt': args.attempt,
              'native_archive_sha256': ARCHIVE_SHA,
              'fixture_source_sha256': digest(HERE / 'history_fixture_test.go.source'),
              'source_files': manifest['files'], 'module_sha256': module_hashes,
              **toolchain_hashes, 'go_version': version,
              'python_version': list(sys.version_info[:3]),
              'build_outputs': stage_files, 'command_receipts': receipts,
              'supervision_policy': SUPERVISION_POLICY,
              'independent_runtime_approval': False})
    build_receipt_sha = digest(build_receipt)
    stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(stage_fd)
    finally:
        os.close(stage_fd)
    result = work / 'result'
    result.mkdir(mode=0o700)
    receipts.append(step(work, 'native-corpus', 720, 1536,
                         [*PYTHON, HERE / 'public_contract.py',
                          '--generator', stage / 'native-history-fixture',
                          '--oracle', stage / 'native-profile-oracle',
                          '--source-receipt', stage / 'history-fixture-source.json',
                          '--build-receipt', build_receipt,
                          '--build-receipt-sha256', build_receipt_sha,
                          '--output', result / 'public-corpus.json'], env, work))
    corpus = json.loads(small(result / 'public-corpus.json', 32 << 20))
    require(corpus['native_source_sha256'] == ARCHIVE_SHA and len(corpus['controls']) == 28,
            'incomplete original native corpus')
    require(not args.export.exists(), 'export must be exclusive')
    args.export.mkdir(mode=0o700)
    export = args.export.resolve()
    copy_exact(result / 'public-corpus.json', export / 'public-corpus.json', limit=32 << 20)
    require(digest(build_receipt) == build_receipt_sha, 'build receipt changed after native proof')
    copy_exact(build_receipt, export / 'build-provenance.json', limit=1 << 20)
    new_json(export / 'command-receipts.json', receipts)
    cache_bytes = sum(path.stat().st_size for path in (work / 'go-mod-cache').rglob('*') if path.is_file())
    provenance = {'schema': 1, 'scope': 'synthetic native artifact generation/verification only',
                  'source_head': args.head, 'workflow_head': args.workflow_head,
                  'source_manifest_sha256': args.manifest_sha256,
                  'build_receipt_sha256': build_receipt_sha,
                  'native_archive_url': ARCHIVE_URL, 'native_archive_sha256': ARCHIVE_SHA,
                  'source_files': manifest['files'], 'module_sha256': module_hashes,
                  'go_version': version, 'python_version': list(sys.version_info[:3]),
                  **toolchain_hashes,
                  'build_outputs': stage_files, 'public_module_cache_bytes': cache_bytes,
                  'runner_physical_memory_bytes': memory_bytes, 'initial_free_scratch_bytes': free_disk,
                  'corpus_sha256': digest(export / 'public-corpus.json'),
                  'root_protocol': json.loads(small(result / 'root-protocol.json', 16384)),
                  'supervision_policy': SUPERVISION_POLICY,
                  'independent_runtime_approval': False,
                  'whole_tree_termination_proven': False,
                  'sampled_budget_not_os_cap': True, 'elapsed_seconds': round(time.monotonic() - started, 3)}
    new_json(export / 'provenance.json', provenance)
    sums = ''.join(digest(path) + '  ' + path.name + '\n' for path in sorted(export.iterdir()))
    new_bytes(export / 'SHA256SUMS', sums.encode())
    require({path.name for path in export.iterdir()} == EXPORT_NAMES, 'unexpected export file')
    for line in sums.splitlines():
        expected, name = line.split('  ', 1)
        require(digest(export / name) == expected, 'export read-back differs')
    require(sum(path.stat().st_size for path in export.iterdir()) <= 36 << 20, 'export exceeds bound')
    # Build caches are disposable only after the independent evidence copy is read back.
    # Bounded command logs remain until runner disposal; never broad sudo rm.
    for name in ('native', 'go-cache', 'go-mod-cache', 'gopath', 'tmp', 'home', 'stage'):
        path = work / name
        if name == 'go-mod-cache':
            for child in path.rglob('*'):
                if child.is_dir():
                    child.chmod(0o700)
        shutil.rmtree(path)
    print(json.dumps({'result': 'passed', 'source_manifest_sha256': args.manifest_sha256,
                      'corpus_sha256': provenance['corpus_sha256'], 'export_files': sorted(EXPORT_NAMES)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest='mode', required=True)
    child = modes.add_parser('download'); child.add_argument('destination', type=Path)
    child = modes.add_parser('run')
    for name in ('work', 'export', 'go'):
        child.add_argument('--' + name, required=True, type=Path)
    for name in ('manifest-sha256', 'run-id', 'attempt', 'head', 'workflow-head'):
        child.add_argument('--' + name, required=True)
    args = parser.parse_args()
    if args.mode == 'download':
        download(args.destination)
    else:
        run(args)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # No traceback, argv, environment or arbitrary file content in CI console.
        print('public native workflow refused: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
