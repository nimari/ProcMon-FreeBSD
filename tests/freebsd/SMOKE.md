# Isolated FreeBSD DTrace capture experiment

This standalone fixture checks the native `freebsd` syscall provider independently
of the application and libdtrace backend. Target: FreeBSD 15.1 / amd64.

## What it checks

- One fixture PID, two worker threads, and a main thread with independent
  userspace observations for exactly 16 `openat`/`read`/`write` calls.
- Successful calls, `EBADF`, and `ENOENT`; raw DTrace results and its `errno`
  variable are compared against libc's results and errno values.
- Entry/return pairing by PID, thread ID, syscall, and entry timestamp.
- Positive durations and overlapping reads blocked on two independent pipes.
- Pathnames longer than the 64-byte capture limit, with explicitly bounded
  `copyinstr` output. On the inspected target, `copyinstr(address, 64)` yields
  up to 64 payload bytes; a future C buffer needs separate room for a terminator.
  This tests truncation, not invalid-pointer fault recovery.
- A fixture completion record, process exit, and DTrace diagnostics. Missing,
  extra, mismatched, or incomplete events fail verification.

Recorded syscall actions filter to DTrace's `$target` PID. The named native
syscall probes themselves are instrumented system-wide; other processes do not
produce workload records. Explicit `getpgid` markers delimit the workload,
excluding dynamic-loader calls and the fixture's final output. DTrace starts
the fixture with `-c`; the fixture requires a nonroot UID and drops elevated
credentials before the workload.

This experiment does not validate libdtrace integration, system-wide capture,
restarts/non-returning syscalls, general schemas, arbitrary binary buffers,
pointer-valued/valid-negative results, event-loss pressure, arbitrary cancellation,
stack capture, symbols, persistence/replay, or alignment with userspace
`CLOCK_MONOTONIC`. Test pathnames are ASCII. Probe stability is `Private` on
the inspected VM; cross-release behavior requires separate validation.

## Run on the VM

Prerequisites: base C compiler and pthreads, user-loaded DTrace modules, and
authorized `doas` access to `/usr/sbin/dtrace`. CMake, Ninja, and package installs
are unnecessary. Do not load modules or change privilege/boot policies implicitly.

Use an ordinary user shell (`/bin/sh`) and copy the two source files into a new,
private temporary directory. The following assumes the current directory contains
the copied files. Save the temporary path for the cleanup step.

```sh
testdir=$(mktemp -d /tmp/procmon-smoke.XXXXXX)
chmod 700 "$testdir"
cp syscall_fixture.c dtrace_smoke.d "$testdir/"
cc -std=c11 -Wall -Wextra -Werror -O0 -g -pthread \
    "$testdir/syscall_fixture.c" -o "$testdir/syscall_fixture"

# Exit if compilation fails. Do not run stale output.
test -x "$testdir/syscall_fixture" || exit 1
workload_uid=$(id -u)
workload_gid=$(id -g)
test "$workload_uid" -ne 0 || exit 1

# The fixture has an alarm and the D program has an independent timeout.
doas /usr/sbin/dtrace -q -s "$testdir/dtrace_smoke.d" \
    -c "$testdir/syscall_fixture $testdir $workload_uid $workload_gid" \
    >"$testdir/capture.tsv" 2>"$testdir/dtrace.stderr"
capture_status=$?
printf 'DTrace exit status: %s\n' "$capture_status"
```

Use a temporary path without whitespace for `-c` in this experiment. The fixture
has an eight-second alarm, and the D program has a ten-second timeout. Neither is
a performance threshold. The 50 ms pipe delay provides an overlap opportunity;
the verifier requires observed overlap rather than assuming scheduling order.
The fixture unlinks its own test files on the normal path; temporary-directory
cleanup is still required after failed or interrupted runs.

Retrieve both output files to the development machine and run this Python 3
verifier there. Pass the saved DTrace exit status and the expected ordinary UID
and GID as additional arguments. Python need not be installed on the VM.

```sh
python3 - capture.tsv dtrace.stderr 0 EXPECTED_UID EXPECTED_GID <<'PY'
from collections import defaultdict
from pathlib import Path
import sys

trace, diagnostics = Path(sys.argv[1]), Path(sys.argv[2])
assert int(sys.argv[3]) == 0, 'DTrace command failed'
expected_uid, expected_gid = map(int, sys.argv[4:6])
assert expected_uid != 0
assert not diagnostics.read_text().strip(), diagnostics.read_text()
rows = [line.split('\t') for line in trace.read_text().splitlines() if line]
assert not [r for r in rows if r[0] in ('FAIL', 'FIXTURE_FAIL')]
allowed = {'BEGIN', 'START', 'STOP', 'ENTRY', 'EVENT', 'IDENTITY',
           'EXPECT', 'FIXTURE', 'TARGET_EXIT', 'END'}
assert all(r[0] in allowed for r in rows), 'unexpected output'

def one(tag):
    matches = [r for r in rows if r[0] == tag]
    assert len(matches) == 1, (tag, matches)
    return matches[0]

pid = int(one('BEGIN')[1])
start, stop = one('START'), one('STOP')
assert int(start[1]) == int(stop[1]) == pid
assert int(start[2]) < int(stop[2])
assert one('IDENTITY') == ['IDENTITY', str(pid), str(expected_uid), str(expected_gid)]
assert one('FIXTURE') == ['FIXTURE', str(pid), '16', '0']
assert one('TARGET_EXIT') == ['TARGET_EXIT', str(pid), '0']
assert one('END') == ['END']
entries, events, expected = {}, {}, defaultdict(list)
for r in rows:
    if r[0] == 'EXPECT':
        assert len(r) == 10 and int(r[1]) == pid
        expected[int(r[2])].append(r)
    elif r[0] in ('ENTRY', 'EVENT'):
        assert len(r) == (8 if r[0] == 'ENTRY' else 11)
        assert int(r[1]) == pid
        key = (int(r[2]), r[3], int(r[4]))
        destination = entries if r[0] == 'ENTRY' else events
        assert key not in destination, ('duplicate', key)
        destination[key] = r
assert len(entries) == len(events) == sum(map(len, expected.values())) == 16
assert entries.keys() == events.keys()
assert len(expected) == 3
blocked = []
for tid, observations in expected.items():
    observations.sort(key=lambda r: int(r[4]))
    assert [int(r[4]) for r in observations] == list(range(len(observations)))
    actual = sorted((r for k, r in events.items() if k[0] == tid),
                    key=lambda r: int(r[4]))
    assert len(actual) == len(observations)
    for e, r in zip(observations, actual):
        entry = entries[(tid, r[3], int(r[4]))]
        assert r[3] == e[3]
        assert list(map(int, r[6:10])) == list(map(int, (e[7], e[8], e[5], e[6])))
        assert entry[5:7] == r[8:10]
        assert entry[7] == r[10] == e[9][:64]
        assert len(r[10].encode()) <= 64
        began, duration = int(r[4]), int(r[5])
        assert int(start[2]) <= began < began + duration <= int(stop[2])
        if e[3] == 'read' and e[6:9] == ['1', '1', '0']:
            blocked.append((began, began + duration, tid))
assert len(blocked) == 2 and blocked[0][2] != blocked[1][2]
assert max(r[0] for r in blocked) < min(r[1] for r in blocked), 'no read overlap'
assert sum(r[8] != '0' for group in expected.values() for r in group) == 6
assert sum(r[3] == 'openat' and len(r[9]) > 64
           for group in expected.values() for r in group) == 4
print('PASS: 16 paired calls, 3 threads, 6 expected errors, 4 bounded paths, overlapping reads')
PY
```

An empty stderr file and complete matching records are required; do not accept
a partial trace simply because DTrace exited 0. On the failure path inspect both
outputs. Drop/error diagnostics fail this small run; this is not a pressure test
or proof that a backend can recover from drops.

## Cleanup and rollback

After retrieving the results, delete only the private directory created for this
run, using its exact saved path. Check that the fixture and DTrace child have
exited first; do not kill unrelated tracing sessions. Do not unload user-loaded
modules or change boot settings as part of test cleanup.

```sh
# Substitute the exact mktemp result; do not use an unverified empty variable.
test -n "$testdir" && test -d "$testdir" && rm -rf -- "$testdir"
```

The smoke test is independent of the application build.
