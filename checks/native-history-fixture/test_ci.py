import contextlib
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
                    })

    def test_unknown_stage_and_noninteger_exit_do_not_leak(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            self.assertEqual(self.failed_report(work, 'SECRET_STAGE\nforged log'), {
                'stage': 'unknown', 'command_exit': None,
                'reasons': ['receipt_unavailable'],
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
            self.assertEqual(set(result), {'stage', 'monitor_exit', 'command_exit', 'reasons'})
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
