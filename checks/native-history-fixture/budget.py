#!/usr/bin/env python3
"""Monitor a reviewed public command; this is a polling policy, NOT an OS cap.

Usage: budget.py --label SAFE_LABEL --seconds N --rss-mib N --log-dir DIR
                 --receipt FILE [--allow-unmeasured]
                 -- COMMAND ARGS...
Python >= 3.11 and Darwin /bin/ps are required. DIR must not exist; its parent
and FILE's parent must exist. All destination components must be absolute,
canonical and nonsymlink. New directories are 0700; logs and receipts are 0600,
opened exclusively with O_NOFOLLOW. Logs are SAFE_LABEL.stdout.log and
SAFE_LABEL.stderr.log. The monitor must run unprivileged; there is no privileged
output ownership transfer. Command stdin is inherited unchanged; only its
stdout and stderr are captured.

The command starts a new session/process group. /bin/ps supplies pid, ppid, pgid,
RSS in KiB and stat. Its documented first stat character Z observes the leader's
exit without reaping it (Python os.waitid is unavailable on macOS). Each sample
sums the entire owned group plus descendants reachable from its members and
its unreaped leader in that snapshot. A reachable descendant outside the group
is a failure, never permission to kill a foreign group. The ps state/RSS contract
is documented in apple-oss-distributions/adv_cmds, ps/ps.1.
Unrelated host rows are discarded, not logged. The sampled
aggregate peak is the maximum of these sums: RSS can count shared pages more
than once; it is neither an allocation count nor a measured continuous peak.
By default at least one positive aggregate is required. Only short informational
commands may opt into --allow-unmeasured: missing positive coverage then records
unmeasured/null rather than failing, never proof of zero memory use. This option
does not relax ps errors, sample timing, group cleanup or any other policy.

Samples start nominally every 0.10s, with a 0.30s maximum observed start gap
and a 0.25s deadline per ps invocation, including pipe drainage and parsing. Violations
fail closed. Polling can miss short-lived processes, transient RSS spikes,
escaped/reparented descendants, and descendants created after enumeration.
The RSS overshoot has NO finite byte bound. A deadline/overage initiates TERM,
then KILL after at most the configured grace in a responsive event loop. OS
scheduling, process creation, filesystem I/O and uninterruptible kernel work
can delay detection/cleanup; none of these intervals is an OS-enforced cap.
Only the owned group is signalled. Its leader is kept unreaped until the last
signal, preventing PID/PGID reuse from redirecting cleanup at another group.
All reviewed children must inherit this group: this is not a hostile-process
sandbox or daemon-containment mechanism.

This is a cooperative hosted policy only; process-group accounting is sampled.
Root protocol processes cannot be
forcibly signalled by this unprivileged monitor. Fork/session/reparenting escapes
and privileged survivors are outside its termination guarantee. A disposable
hosted VM's job deadline is a separate provider boundary, not local tree proof;
using that narrower policy requires the separate policy decision before upload.

Each stdout/stderr log stores at most 1 MiB. Crossing either limit fails;
nonblocking selector reads continue during cleanup without pipe deadlock.
The receipt records sampled coverage, actual gaps/overshoot, exit status and
cleanup verification. It omits argv, environment, raw ps output and paths.
Child output is NOT redacted: the caller must supply reviewed public commands
and a clean environment whose output contains only public-build paths/data.
Handled failures produce an fsynced JSON receipt when its fresh destination
is usable. SIGKILL, power loss, unavailable storage or a stuck kernel cannot
promise a completed receipt; a missing/empty/invalid receipt is not success.
"""
import argparse
import datetime as dt
import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

SAMPLE_INTERVAL = 0.10
MAX_SAMPLE_GAP = 0.30
PS_TIMEOUT = 0.25
PS_REAP_TIMEOUT = 0.20
EVENT_INTERVAL = 0.025
TERM_GRACE = 1.0
KILL_GRACE = 1.0
DRAIN_GRACE = 0.50
LOG_LIMIT = 1 << 20
READ_SIZE = 64 << 10
PS_STDOUT_LIMIT = 8 << 20
PS_STDERR_LIMIT = 8 << 10


class MonitorProblem(Exception):
    """A constant, public failure code, never an exception containing paths."""


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise MonitorProblem('invalid_arguments')


def write_all(fd, data):
    view = memoryview(data)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise MonitorProblem('output_write_failure')
        view = view[count:]


def open_parent(path):
    # Walk by descriptors, so O_NOFOLLOW protects ancestors as well as leaves.
    parts = path.split('/')
    if (not path.startswith('/') or any(p in ('', '.', '..') for p in parts[1:])
            or len(parts) < 2):
        raise MonitorProblem('noncanonical_output_path')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        for part in parts[1:-1]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def new_file(parent_fd, name):
    return os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                   | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)


class Outputs:
    def __init__(self):
        self.receipt_parent = None
        self.receipt = None
        self.log_parent = None
        self.log_dir = None
        self.logs = {}

    def open_receipt(self, path):
        self.receipt_parent, name = open_parent(path)
        self.receipt = new_file(self.receipt_parent, name)
        os.fsync(self.receipt_parent)

    def open_logs(self, path, label):
        self.log_parent, name = open_parent(path)
        os.mkdir(name, 0o700, dir_fd=self.log_parent)
        directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                            | os.O_CLOEXEC, dir_fd=self.log_parent)
        try:
            info = os.fstat(directory)
            if (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700
                    or os.listdir(directory)):
                raise MonitorProblem('invalid_new_log_directory')
        except BaseException:
            os.close(directory)
            raise
        self.log_dir = directory
        for channel in ('stdout', 'stderr'):
            self.logs[channel] = new_file(self.log_dir, label + '.' + channel + '.log')
        os.fsync(self.log_dir)
        os.fsync(self.log_parent)

    def sync_logs(self):
        for fd in self.logs.values():
            os.fsync(fd)
        if self.log_dir is not None:
            os.fsync(self.log_dir)

    def save_receipt(self, receipt):
        data = (json.dumps(receipt, sort_keys=True, indent=2, allow_nan=False)
                + '\n').encode('utf-8')
        # Write once through the original exclusive descriptor; never reopen a
        # pathname or replace an existing caller-owned file.
        write_all(self.receipt, data)
        os.fsync(self.receipt)
        os.fsync(self.receipt_parent)

    def close(self):
        for fd in [*self.logs.values(), self.log_dir, self.log_parent,
                   self.receipt, self.receipt_parent]:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


class Monitor:
    def __init__(self, args, outputs):
        self.args = args
        self.outputs = outputs
        self.selector = None
        self.proc = None
        self.pgid = None
        self.leader_exit = None
        self.leader_exited_at = None
        self.leader_reaped = False
        self.signalling_closed = False
        self.group_gone = False
        self.started = None
        self.started_utc = None
        self.deadline = None
        self.finished = None
        self.interrupted = None
        self.failures = []
        self.stage = 'running'
        self.term_at = None
        self.kill_at = None
        self.term_sent = False
        self.kill_sent = False
        self.streams = {
            name: {'stored_bytes': 0, 'observed_bytes': 0, 'eof': False,
                   'limit_exceeded': False}
            for name in ('stdout', 'stderr')
        }
        self.drain_failed = False
        self.ps = None
        self.ps_started = None
        self.ps_buffers = None
        self.ps_eof = None
        self.last_sample_start = None
        self.next_sample = None
        self.samples = 0
        self.positive_samples = 0
        self.peak_kib = None
        self.peak_process_count = None
        self.max_sample_gap = 0.0
        self.max_sample_duration = 0.0
        self.escaped_observed = False
        self.max_escaped_count = 0

    def fail(self, code):
        if code not in self.failures:
            self.failures.append(code)

    def on_signal(self, signum, frame):
        if self.interrupted is None:
            self.interrupted = signum

    def add_pipe(self, pipe, source, channel):
        os.set_blocking(pipe.fileno(), False)
        self.selector.register(pipe, selectors.EVENT_READ, (source, channel))

    def close_pipe(self, pipe):
        try:
            self.selector.unregister(pipe)
        except (KeyError, ValueError):
            pass
        pipe.close()


    def signal_group(self, signum):
        if self.proc is None or self.signalling_closed:
            return
        try:
            os.killpg(self.pgid, signum)
        except ProcessLookupError:
            return
        except OSError:
            self.fail('group_signal_failure')
            return
        if signum == signal.SIGTERM:
            self.term_sent = True
        elif signum == signal.SIGKILL:
            self.kill_sent = True

    def begin_termination(self, now):
        if self.stage == 'running':
            self.stage = 'term'
            self.term_at = now
            self.signal_group(signal.SIGTERM)

    def advance_termination(self, now):
        if self.stage == 'term' and now >= self.term_at + TERM_GRACE:
            self.stage = 'kill'
            self.kill_at = now
            self.signal_group(signal.SIGKILL)

    def start_sample(self, now):
        now = time.monotonic()
        previous = self.started if self.last_sample_start is None else self.last_sample_start
        gap = now - previous
        self.max_sample_gap = max(self.max_sample_gap, gap)
        if gap > MAX_SAMPLE_GAP:
            raise MonitorProblem('sampling_gap_exceeded')
        self.last_sample_start = now
        self.ps_started = now
        self.next_sample = now + SAMPLE_INTERVAL
        self.ps_buffers = {'stdout': bytearray(), 'stderr': bytearray()}
        self.ps_eof = {'stdout': False, 'stderr': False}
        self.ps = subprocess.Popen(
            ['/bin/ps', '-A', '-o', 'pid=,ppid=,pgid=,rss=,stat='],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, cwd='/', env={'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'})
        self.add_pipe(self.ps.stdout, 'ps', 'stdout')
        self.add_pipe(self.ps.stderr, 'ps', 'stderr')

    def read_ready(self, key):
        source, channel = key.data
        try:
            data = os.read(key.fd, READ_SIZE)
        except BlockingIOError:
            return
        if not data:
            self.close_pipe(key.fileobj)
            if source == 'command':
                self.streams[channel]['eof'] = True
            else:
                self.ps_eof[channel] = True
            return
        if source == 'ps':
            limit = PS_STDOUT_LIMIT if channel == 'stdout' else PS_STDERR_LIMIT
            if len(self.ps_buffers[channel]) + len(data) > limit:
                raise MonitorProblem('ps_output_limit_exceeded')
            self.ps_buffers[channel].extend(data)
            return
        stream = self.streams[channel]
        stream['observed_bytes'] += len(data)
        available = LOG_LIMIT - stream['stored_bytes']
        if available:
            kept = data[:available]
            write_all(self.outputs.logs[channel], kept)
            stream['stored_bytes'] += len(kept)
        if stream['observed_bytes'] > LOG_LIMIT:
            stream['limit_exceeded'] = True
            self.fail(channel + '_limit_exceeded')
            self.begin_termination(time.monotonic())

    def parse_sample(self, raw):
        rows = {}
        children = {}
        for line in raw.splitlines():
            columns = line.split()
            if (len(columns) != 5 or any(not v.isdigit() for v in columns[:4])
                    or not columns[4].isascii() or len(columns[4]) > 16):
                raise MonitorProblem('invalid_ps_snapshot')
            pid, ppid, pgid, rss = map(int, columns[:4])
            if pid in rows:
                raise MonitorProblem('invalid_ps_snapshot')
            rows[pid] = (ppid, pgid, rss, columns[4])
            children.setdefault(ppid, []).append(pid)
        # Empty/truncated/incorrect ps output must not certify that a group died.
        if os.getpid() not in rows:
            raise MonitorProblem('invalid_ps_snapshot')
        leader = rows.get(self.proc.pid)
        if leader is None or leader[0] != os.getpid():
            # A partial/malformed snapshot cannot certify absence. The child
            # remains unreaped by construction, so emergency group cleanup is
            # still safe even when ps cannot report it.
            raise MonitorProblem('invalid_ps_leader')
        if leader[3].startswith(b'Z') and self.leader_exited_at is None:
            self.leader_exited_at = time.monotonic()
        selected = {pid for pid, row in rows.items() if row[1] == self.pgid}
        pending = list(selected | {self.proc.pid})
        visited = set(pending)
        if self.proc.pid in rows:
            selected.add(self.proc.pid)
        while pending:
            for pid in children.get(pending.pop(), ()):
                if pid not in visited:
                    visited.add(pid)
                    selected.add(pid)
                    pending.append(pid)
        aggregate = sum(rows[pid][2] for pid in selected)
        escaped = sum(rows[pid][1] != self.pgid for pid in selected)
        self.samples += 1
        if aggregate > 0:
            self.positive_samples += 1
        if self.peak_kib is None or aggregate > self.peak_kib:
            self.peak_kib = aggregate
            self.peak_process_count = len(selected)
        if escaped:
            self.escaped_observed = True
            self.max_escaped_count = max(self.max_escaped_count, escaped)
            self.fail('descendant_escaped_owned_group')
        if aggregate > self.args.rss_mib * 1024:
            self.fail('rss_budget_exceeded')
        remaining = {pid for pid in selected
                     if pid != self.proc.pid and rows[pid][1] == self.pgid}
        return bool(remaining)

    def reap_and_verify(self):
        # No signal may be sent after this point: releasing the leader permits
        # PID reuse. A positive final killpg(0) probe fails but is never killed.
        self.signalling_closed = True
        try:
            self.leader_exit = self.proc.wait(timeout=0)
        except subprocess.TimeoutExpired:
            self.fail('leader_reap_failure')
            return
        self.leader_reaped = True
        if self.leader_exit != 0:
            self.fail('command_exit_nonzero')
        try:
            os.killpg(self.pgid, 0)
        except ProcessLookupError:
            self.group_gone = True
        except OSError:
            self.fail('group_verification_failure')
        else:
            self.fail('owned_group_remains')

    def finish_sample(self, now):
        duration = now - self.ps_started
        self.max_sample_duration = max(self.max_sample_duration, duration)
        if duration > PS_TIMEOUT:
            raise MonitorProblem('ps_deadline_exceeded')
        result = self.ps.poll()
        if result is None or not all(self.ps_eof.values()):
            return False
        if result != 0 or self.ps_buffers['stderr']:
            raise MonitorProblem('ps_failed')
        remaining = self.parse_sample(self.ps_buffers['stdout'])
        duration = time.monotonic() - self.ps_started
        self.max_sample_duration = max(self.max_sample_duration, duration)
        if duration > PS_TIMEOUT:
            raise MonitorProblem('ps_deadline_exceeded')
        sample_start = self.ps_started
        self.ps = None
        self.ps_buffers = None
        if time.monotonic() >= self.deadline:
            self.fail('deadline_exceeded')
        if self.leader_exited_at is None or sample_start < self.leader_exited_at:
            return False
        if remaining:
            self.fail('child_group_leftovers')
            return False
        drained = all(stream['eof'] for stream in self.streams.values())
        if not drained and not self.drain_failed:
            return False
        if not self.positive_samples and not self.args.allow_unmeasured:
            self.fail('rss_unmeasured')
        self.reap_and_verify()
        return True

    def stop_ps(self):
        if self.ps is None:
            return
        try:
            if self.ps.poll() is None:
                self.ps.kill()
            self.ps.wait(timeout=PS_REAP_TIMEOUT)
        except (OSError, subprocess.TimeoutExpired):
            self.fail('ps_cleanup_failure')
        finally:
            for pipe in (self.ps.stdout, self.ps.stderr):
                if pipe is not None and not pipe.closed:
                    self.close_pipe(pipe)
            self.ps = None
            self.ps_buffers = None

    def emergency_cleanup(self):
        if self.proc is None or self.signalling_closed:
            return
        # Independent of ps/selectors: even a broken monitor attempts bounded
        # TERM/KILL cleanup. Keep the leader unreaped throughout both signals.
        self.begin_termination(time.monotonic())
        while self.stage != 'kill':
            now = time.monotonic()
            self.advance_termination(now)
            if self.stage != 'kill':
                time.sleep(min(EVENT_INTERVAL, max(0.0, self.term_at + TERM_GRACE - now)))
        until = self.kill_at + KILL_GRACE
        while time.monotonic() < until:
            time.sleep(min(EVENT_INTERVAL, max(0.0, until - time.monotonic())))
        try:
            self.reap_and_verify()
        except (OSError, MonitorProblem):
            self.fail('cleanup_verification_failure')

    def run(self, command):
        try:
            self.selector = selectors.DefaultSelector()
            self.started = time.monotonic()
            self.started_utc = dt.datetime.now(dt.timezone.utc).isoformat()
            self.deadline = self.started + self.args.seconds
            self.next_sample = self.started
            self.proc = subprocess.Popen(
                command, stdin=None, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True, close_fds=True)
            self.pgid = self.proc.pid
            self.add_pipe(self.proc.stdout, 'command', 'stdout')
            self.add_pipe(self.proc.stderr, 'command', 'stderr')
            while True:
                now = time.monotonic()
                if self.interrupted is not None:
                    self.fail('interrupted')
                if now >= self.deadline:
                    self.fail('deadline_exceeded')
                if (self.leader_exited_at is not None
                        and now >= self.leader_exited_at + DRAIN_GRACE
                        and not all(s['eof'] for s in self.streams.values())):
                    self.drain_failed = True
                    self.fail('output_drain_timeout')
                if self.failures:
                    self.begin_termination(now)
                self.advance_termination(now)
                if self.stage == 'kill' and now >= self.kill_at + KILL_GRACE:
                    self.fail('cleanup_deadline_exceeded')
                    break
                if self.ps is not None and self.finish_sample(now):
                    break
                if self.ps is None and now >= self.next_sample:
                    self.start_sample(now)
                for key, _ in self.selector.select(EVENT_INTERVAL):
                    self.read_ready(key)
        except MonitorProblem as exc:
            self.fail(exc.args[0])
        except BaseException:
            # Never expose command arguments, exception paths or environment.
            self.fail('monitor_failure')
        finally:
            # Start group cleanup before waiting for a faulty ps helper.
            if self.proc is not None and not self.signalling_closed:
                self.begin_termination(time.monotonic())
            try:
                self.stop_ps()
            except BaseException:
                self.fail('ps_cleanup_failure')
            try:
                self.emergency_cleanup()
            except BaseException:
                self.fail('cleanup_failure')
            if self.proc is not None:
                for pipe in (self.proc.stdout, self.proc.stderr):
                    if pipe is not None and not pipe.closed:
                        try:
                            self.close_pipe(pipe)
                        except OSError:
                            self.fail('pipe_close_failure')
            if self.selector is not None:
                self.selector.close()
            self.finished = time.monotonic()
            if self.deadline is not None and self.finished >= self.deadline:
                self.fail('deadline_exceeded')
            if not self.positive_samples and not self.args.allow_unmeasured:
                self.fail('rss_unmeasured')
            if not self.group_gone:
                self.fail('owned_group_not_verified_gone')

    def receipt(self):
        end = self.finished if self.finished is not None else time.monotonic()
        elapsed = None if self.started is None else end - self.started
        return {
            'schema': 'native-budget-monitor/v1',
            'label': self.args.label,
            'status': 'failed' if self.failures else 'ok',
            'failures': list(self.failures),
            'started_at_utc': self.started_utc,
            'elapsed_seconds': elapsed,
            'deadline_monotonic_seconds': self.deadline,
            'deadline_overshoot_seconds': (None if self.deadline is None else
                                           max(0.0, end - self.deadline)),
            'budget_seconds': self.args.seconds,
            'rss_budget_kib': self.args.rss_mib * 1024,
            'measurement_status': 'measured' if self.positive_samples else 'unmeasured',
            'positive_measurement_required': not self.args.allow_unmeasured,
            'sampled_aggregate_peak_kib': self.peak_kib if self.positive_samples else None,
            'peak_sample_process_count': self.peak_process_count,
            'sample_count': self.samples,
            'positive_sample_count': self.positive_samples,
            'sample_interval_seconds': SAMPLE_INTERVAL,
            'max_allowed_sample_start_gap_seconds': MAX_SAMPLE_GAP,
            'max_observed_sample_start_gap_seconds': self.max_sample_gap,
            'ps_deadline_seconds': PS_TIMEOUT,
            'max_observed_ps_duration_seconds': self.max_sample_duration,
            'peak_scope': 'owned_process_group_and_snapshot_reachable_descendants',
            'escaped_descendants_observed': self.escaped_observed,
            'max_escaped_descendants_in_sample': self.max_escaped_count,
            'limits_are_os_caps': False,
            'rss_overshoot_bound_kib': None,
            'rss_overshoot_bound_reason': 'unbounded_between_samples_and_during_cleanup',
            'event_loop_interval_seconds': EVENT_INTERVAL,
            'term_grace_seconds': TERM_GRACE,
            'kill_verification_grace_seconds': KILL_GRACE,
            'output_drain_grace_seconds': DRAIN_GRACE,
            'output_limit_bytes_per_stream': LOG_LIMIT,
            'output_read_chunk_bytes': READ_SIZE,
            'stdout': self.streams['stdout'].copy(),
            'stderr': self.streams['stderr'].copy(),
            'command_exit_code': self.leader_exit,
            'interrupted_signal': self.interrupted,
            'cleanup': {
                'owned_pgid': self.pgid,
                'term_sent': self.term_sent,
                'kill_sent': self.kill_sent,
                'leader_reaped': self.leader_reaped,
                'owned_group_verified_gone': self.group_gone,
                'foreign_groups_signalled': False,
            },
        }


def parse_args(argv):
    parser = SafeParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--label', required=True)
    parser.add_argument('--seconds', required=True, type=float)
    parser.add_argument('--rss-mib', required=True, type=int)
    parser.add_argument('--log-dir', required=True)
    parser.add_argument('--receipt', required=True)
    parser.add_argument('--allow-unmeasured', action='store_true')
    if argv in (['-h'], ['--help']):
        parser.print_help()
        return None, None
    if '--' not in argv:
        raise MonitorProblem('missing_command_separator')
    separator = argv.index('--')
    args = parser.parse_args(argv[:separator])
    command = argv[separator + 1:]
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', args.label):
        raise MonitorProblem('invalid_label')
    if (not math.isfinite(args.seconds) or args.seconds <= 0
            or not math.isfinite(time.monotonic() + args.seconds)
            or args.rss_mib <= 0 or args.rss_mib > ((1 << 63) - 1) // 1024):
        raise MonitorProblem('invalid_budget')
    if not command or not command[0] or any('\0' in value for value in command):
        raise MonitorProblem('invalid_command')
    return args, command


def main():
    try:
        args, command = parse_args(sys.argv[1:])
    except (MonitorProblem, ValueError, OverflowError):
        print('budget: invalid arguments; no command launched', file=sys.stderr)
        return 2
    if args is None:
        return 0
    outputs = Outputs()
    if os.getuid() == 0 or os.geteuid() == 0:
        print('budget: unprivileged monitor required', file=sys.stderr)
        return 2
    monitor = Monitor(args, outputs)
    handlers = {}
    try:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
            handlers[signum] = signal.signal(signum, monitor.on_signal)
        # An inherited SIGCHLD=SIG_IGN would auto-reap the ownership anchor.
        handlers[signal.SIGCHLD] = signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        outputs.open_receipt(args.receipt)
        outputs.open_logs(args.log_dir, args.label)
        if sys.version_info < (3, 11):
            raise MonitorProblem('unsupported_python_version')
        if monitor.interrupted is None:
            monitor.run(command)
        else:
            monitor.fail('interrupted')
    except MonitorProblem as exc:
        monitor.fail(exc.args[0])
    except BaseException:
        monitor.fail('setup_failure')
    try:
        outputs.sync_logs()
    except BaseException:
        monitor.fail('log_sync_failure')
    if monitor.interrupted is not None:
        monitor.fail('interrupted')
    if monitor.started is None:
        monitor.fail('command_not_started')
    result = 0 if not monitor.failures else 1
    if monitor.interrupted is not None:
        result = 128 + monitor.interrupted
    try:
        if outputs.receipt is None:
            raise MonitorProblem('receipt_unavailable')
        receipt = monitor.receipt()
        receipt['monitor_exit_code'] = result
        outputs.save_receipt(receipt)
    except BaseException:
        result = 1
        print('budget: receipt persistence failed; result is not success', file=sys.stderr)
    finally:
        outputs.close()
        for signum, handler in handlers.items():
            signal.signal(signum, handler)
    if result:
        print('budget: failed; inspect the new receipt if available', file=sys.stderr)
    return result


if __name__ == '__main__':
    sys.exit(main())
