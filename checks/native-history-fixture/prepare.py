#!/usr/bin/env python3
"""Extract the exact public v0.1.16 archive and add the native byte fixture.

This command does not build or execute Go. It refuses an existing destination
and verifies the archive SHA256 before extracting regular files/directories.
The generated source receipt binds the archive and the added fixture.

The compiled fixture uses unchanged native writers and verifyArtifacts with
real Darwin ownership/mode/ACL checks. Host observations and category outcomes
are synthetic inputs: this is byte-contract evidence, not Collect, approval,
launcher provenance, recipes, reboot, host isolation or service deployment.
See PUBLIC-PLAN.md for the separately reviewed hosted workflow.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import tarfile

ARCHIVE_SHA256 = '9440aedf29fa10b9fb879f018cdd034162c20527732176e999d239d566647ba2'
PREFIX = 'macserve-0.1.16'
ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--archive', required=True, type=Path)
    args = parser.parse_args()
    destination = args.destination.resolve()
    if not args.destination.is_absolute() or destination == ROOT or ROOT in destination.parents:
        parser.error('destination must be an absolute new directory outside the work tree')
    if destination.exists():
        parser.error('destination must not already exist')
    # Extract only the exact reviewed release, never a mutable projection of it.
    with args.archive.open('rb') as source:
        if hashlib.file_digest(source, 'sha256').hexdigest() != ARCHIVE_SHA256:
            parser.error('native release archive digest mismatch')
        source.seek(0)
        with tarfile.open(fileobj=source, mode='r:gz') as archive:
            members = archive.getmembers()
            paths = set()
            for member in members:
                parts = PurePosixPath(member.name).parts
                if (not parts or parts[0] != PREFIX or '..' in parts
                        or not (member.isdir() or member.isfile()) or member.name in paths):
                    parser.error('unexpected native source archive member')
                paths.add(member.name)
            destination.mkdir(mode=0o700)
            for member in members:
                relative = PurePosixPath(member.name).relative_to(PREFIX)
                target = destination / relative
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True, mode=0o700)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    with archive.extractfile(member) as incoming, target.open('xb') as outgoing:
                        shutil.copyfileobj(incoming, outgoing)
                    target.chmod(0o600)
    addition = Path(__file__).with_name('history_fixture_test.go.source')
    with (destination / 'internal/qualification/history_fixture_test.go').open('xb') as output:
        output.write(addition.read_bytes())
    receipt = {'native_archive_sha256': ARCHIVE_SHA256,
               'fixture_source_sha256': hashlib.sha256(addition.read_bytes()).hexdigest(),
               'build_executed': False, 'native_execution': False}
    (destination / 'history-fixture-source.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))
    print('After clearance, in', destination)
    print('go test -c -o /absolute/output/native-history-fixture ./internal/qualification')


if __name__ == '__main__':
    main()
