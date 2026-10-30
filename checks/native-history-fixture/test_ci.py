import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('native_ci', Path(__file__).with_name('ci.py'))
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)

EMPTY_EVIDENCE = {
    'measurements': dict.fromkeys((
        'elapsed_seconds', 'deadline_overshoot_seconds',
        'max_observed_ps_duration_seconds', 'max_observed_sample_start_gap_seconds',
        'sample_count', 'positive_sample_count', 'peak_sample_process_count',
        'sampled_aggregate_peak_kib')),
    'build_hashes': dict.fromkeys((
        'native_archive_sha256', 'fixture_source_sha256', 'go_executable_sha256',
        'python_executable_sha256', 'native-history-fixture', 'native-profile-oracle',
        'history-fixture-source.json', 'build_receipt_sha256')),
}


class PublicFailureTests(unittest.TestCase):
    def failed_report(self, work, label='compile-history'):
        # Force a real monitor setup refusal without overwriting the untrusted
        # receipt fixture or running a command. Exercise the existing step API.
        (work / (label + '-logs')).mkdir(exist_ok=True)
        report = io.StringIO()
        with contextlib.redirect_stderr(report), self.assertRaises(RuntimeError):
            ci.step(work.resolve(), label, 5, 256, ['/usr/bin/false'], os.environ.copy(), work)
        self.assertNotEqual(report.getvalue(), '', 'failed step omitted its public diagnostic')
        self.assertNotIn('SECRET', report.getvalue())
        result = json.loads(report.getvalue())
        self.assertIn(result.pop('monitor_exit'), (1, 2))
        return result

    def test_ordered_failures_and_bounded_evidence_preserve_privacy(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            failures = ['ps_deadline_exceeded', 'SECRET_REASON', 'group_signal_failure',
                        'command_exit_nonzero']
            measurements = {
                'elapsed_seconds': 2.5, 'deadline_overshoot_seconds': 0,
                'max_observed_ps_duration_seconds': .23,
                'max_observed_sample_start_gap_seconds': .11,
                'sample_count': 3, 'positive_sample_count': 2,
                'peak_sample_process_count': 4, 'sampled_aggregate_peak_kib': 1024,
            }
            (work / 'compile-history.json').write_text(json.dumps({
                'schema': 'native-budget-monitor/v1', 'label': 'compile-history',
                'failures': failures, 'command_exit_code': -15, **measurements,
                'cleanup': {'owned_pgid': 'SECRET_PID', 'errno': 'SECRET_ERRNO'},
                'stdout': 'SECRET_STDOUT', 'uid': 'SECRET_UID',
            }))
            (work / 'stage').mkdir()
            build = {'schema': 1, 'native_archive_sha256': ci.ARCHIVE_SHA,
                     'independent_runtime_approval': False,
                     'fixture_source_sha256': 'a' * 64,
                     'go_executable_sha256': 'b' * 64,
                     'python_executable_sha256': 'SECRET_HASH',
                     'build_outputs': {'native-history-fixture': 'c' * 64,
                                       'native-profile-oracle': 'd' * 64,
                                       'history-fixture-source.json': 'e' * 64,
                                       'SECRET_PATH': 'SECRET_VALUE'},
                     'command_receipts': [{'argv': 'SECRET_ARGV'}]}
            raw = json.dumps(build).encode()
            (work / 'stage/build-provenance.json').write_bytes(raw)
            result = self.failed_report(work)
            self.assertEqual(result, {
                'stage': 'compile-history', 'command_exit': -15,
                'reasons': ['ps_deadline_exceeded', 'unclassified_failure',
                            'group_signal_failure', 'command_exit_nonzero'],
                'measurements': measurements,
                'build_hashes': {'native_archive_sha256': ci.ARCHIVE_SHA,
                                'fixture_source_sha256': 'a' * 64,
                                'go_executable_sha256': 'b' * 64,
                                'python_executable_sha256': None,
                                'native-history-fixture': 'c' * 64,
                                'native-profile-oracle': 'd' * 64,
                                'history-fixture-source.json': 'e' * 64,
                                'build_receipt_sha256': hashlib.sha256(raw).hexdigest()},
            })

    def test_invalid_measurements_and_build_receipts_are_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / 'stage').mkdir()
            build_path = work / 'stage/build-provenance.json'
            for invalid in ['SECRET_VALUE', True, -1, float('nan'), float('inf'), 1 << 100]:
                with self.subTest(kind=type(invalid).__name__):
                    (work / 'compile-history.json').write_text(json.dumps({
                        'schema': 'native-budget-monitor/v1', 'label': 'compile-history',
                        'failures': ['ps_deadline_exceeded'],
                        **dict.fromkeys(EMPTY_EVIDENCE['measurements'], invalid),
                    }))
                    build_path.write_text(json.dumps({'schema': 1,
                        'native_archive_sha256': 'SECRET_WRONG_ARCHIVE',
                        'independent_runtime_approval': False,
                        'build_outputs': {'native-history-fixture': 'a' * 64}}))
                    result = self.failed_report(work)
                    self.assertEqual(result['measurements'], EMPTY_EVIDENCE['measurements'])
                    self.assertEqual(result['build_hashes'], EMPTY_EVIDENCE['build_hashes'])
            for raw in ['SECRET_MALFORMED', 'SECRET_OVERSIZE' * (1 << 20)]:
                build_path.write_text(raw)
                self.assertEqual(self.failed_report(work)['build_hashes'],
                                 EMPTY_EVIDENCE['build_hashes'])

    def test_reports_fixed_codes_without_private_receipt_data(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / 'compile-history.json').write_text(json.dumps({
                'schema': 'native-budget-monitor/v1', 'label': 'compile-history',
                'failures': ['rss_budget_exceeded', 'SECRET_REASON\nforged log'],
                'command_exit_code': -9, 'argv': ['SECRET_ARG'],
                'environment': {'TOKEN': 'SECRET_ENV'}, 'stderr': 'SECRET_STDERR',
            }))
            self.assertEqual(self.failed_report(work), {
                'stage': 'compile-history', 'command_exit': -9,
                **EMPTY_EVIDENCE,
                'reasons': ['rss_budget_exceeded', 'unclassified_failure'],
            })

    def test_untrusted_or_unavailable_receipts_remain_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            path = work / 'compile-history.json'
            cases = [None, 'SECRET_MALFORMED', 'SECRET_OVERSIZE' * (128 << 10),
                     json.dumps({'schema': 'native-budget-monitor/v1',
                                 'label': 'SECRET_WRONG_STAGE', 'failures': ['deadline_exceeded']}),
                     json.dumps({'schema': 'native-budget-monitor/v1', 'label': 'compile-history',
                                 'failures': [{'SECRET_KEY': 'SECRET_VALUE'}]})]
            for payload in cases:
                with self.subTest(case='unavailable' if payload is None else len(payload)):
                    if payload is None:
                        path.mkdir()
                    else:
                        if path.is_dir():
                            path.rmdir()
                        path.write_text(payload)
                    self.assertEqual(self.failed_report(work), {
                        'stage': 'compile-history', 'command_exit': None,
                        'reasons': ['receipt_unavailable'],
                        **EMPTY_EVIDENCE,
                    })

    def test_unknown_stage_and_noninteger_exit_do_not_leak(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            self.assertEqual(self.failed_report(work, 'SECRET_STAGE\nforged log'), {
                'stage': 'unknown', 'command_exit': None,
                'reasons': ['receipt_unavailable'],
                **EMPTY_EVIDENCE,
            })
            for exit_code in ['SECRET_EXIT', True, 1 << 100]:
                (work / 'compile-history.json').write_text(json.dumps({
                    'schema': 'native-budget-monitor/v1', 'label': 'compile-history',
                    'failures': ['command_exit_nonzero'], 'command_exit_code': exit_code,
                }))
                result = self.failed_report(work)
                self.assertIsNone(result['command_exit'])
                self.assertEqual(result['reasons'], ['command_exit_nonzero'])

    def test_failed_step_emits_only_safe_report_and_still_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory).resolve()
            report = io.StringIO()
            command = [sys.executable, '-I', '-S', '-c',
                       'import sys,time; print("SECRET_STDOUT"); '
                       'print("SECRET_STDERR", file=sys.stderr); time.sleep(.2); sys.exit(7)']
            with contextlib.redirect_stderr(report), self.assertRaises(RuntimeError):
                ci.step(work, 'go-version', 5, 256, command, os.environ.copy(), work)
            self.assertNotIn('SECRET', report.getvalue())
            result = json.loads(report.getvalue())
            self.assertEqual(set(result), {'stage', 'monitor_exit', 'command_exit', 'reasons',
                                          'measurements', 'build_hashes'})
            self.assertEqual(result['stage'], 'go-version')
            if os.getuid() == 0:
                self.assertEqual(result['monitor_exit'], 2)
                self.assertEqual(result['reasons'], ['receipt_unavailable'])
            else:
                self.assertEqual(result['monitor_exit'], 1)
                self.assertEqual(result['command_exit'], 7)
                self.assertIn('command_exit_nonzero', result['reasons'])


if __name__ == '__main__':
    unittest.main()
