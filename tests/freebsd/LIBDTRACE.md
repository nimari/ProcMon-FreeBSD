# Standalone libdtrace API experiment

Target: FreeBSD 15.1 / amd64. This standalone test reuses
[syscall_fixture.c](syscall_fixture.c) without changing it. It adds a small C
consumer and a binary-record D program; neither is integrated into ProcMon.

## Data and lifecycle

[libdtrace_records.d](libdtrace_records.d) uses `trace()` actions with explicit
64-bit scalar casts and a 65-byte D string slot. The consumer's probe callback
uses the public enabled-probe and record descriptors: action kind, record count,
width, offset, enclosing size, and string termination are checked before reading
payload bytes with `memcpy`. Zero-length assignment descriptors are counted and
skipped rather than interpreted as data fields. Provider/module/function/probe names identify the
small experimental schema. The record callback suppresses libdtrace formatting.

Input arrives through `dtrace_work` callbacks. The consumer does not run or parse
the `dtrace` command. Its TSV output is a test artifact generated from decoded
values, allowing reuse of the existing independent workload comparison.

A gated child is created before opening the library. It drops privileges, waits
until probes are enabled, redirects its output to `fixture.tsv`, and executes
the existing workload. The parent remains privileged for tracing. Its lifecycle
is `open -> register handlers -> set options -> compile -> enable -> go -> work
-> stop -> final work/drain -> close`, with child reaping on success and failure.
The child runs with the explicitly supplied nonroot UID/GID. The parent kills
only its own still-live child during failure cleanup.

Four bounded cases are checked:

| Case | Mechanism and required evidence |
| --- | --- |
| `normal` | Same 16 calls and three threads as the earlier experiment; 37 probe callbacks and 250 data-field callbacks, plus zero-length assignment descriptors; no errors/drops; completed child and final END record. |
| `fault` | A target-scoped `copyinstr(0)` triggers the actual libdtrace error handler; nonzero exit and error count; stop/drain/close/reap. |
| `drop` | A 1 KiB principal buffer and consumption withheld until the short workload exits induce actual buffer drops; nonzero exit and drop callback; completed fixture and stop/drain/close/reap. |
| `startup` | Deliberately invalid D source fails library compilation while the child is gated; probes never start; handle closes and child is reaped. |

The fixture alarm and a ten-second parent polling deadline bound execution.
Signal handlers only set a flag for ordinary cleanup. Arbitrary signal/timeout
behavior, library calls that themselves block, and sustained-load recovery are
not established by these four cases. A 1 KiB buffer is a failure-injection
setting, not the proposed backend buffer size. Drop counts depend on scheduling.
If this setting produces no drops on another machine, report that case as
unverified rather than fabricating or silently accepting a zero count.

The normal test checks that a final drain preserves all records. Kernel tracing
for these named probes is system-wide; actions and injected faults are restricted
to the fixture PID and its explicit markers. No privilege policies, modules,
boot settings, application sources, package files, or trace formats are changed.

## Reproduce in a private VM directory

Use `/bin/sh` as the ordinary VM user. Load required modules only through an
authorized tracing setup. Copy `libdtrace_consumer.c`, `libdtrace_records.d`, and
`syscall_fixture.c` into a fresh mode-0700 directory under `/tmp`; record its
exact path. The following uses `testdir` for that path:

```sh
cc -std=c11 -Wall -Wextra -Werror -O0 -g -pthread \
    "$testdir/syscall_fixture.c" -o "$testdir/syscall_fixture" || exit 1
cc -std=c11 -Wall -Wextra -Werror -O0 -g \
    "$testdir/libdtrace_consumer.c" -o "$testdir/libdtrace_consumer" \
    -ldtrace || exit 1

workload_uid=$(id -u)
workload_gid=$(id -g)
test "$workload_uid" -ne 0 || exit 1
for mode in normal fault drop; do
    mkdir -m 700 "$testdir/$mode" || exit 1
    doas "$testdir/libdtrace_consumer" "$testdir/libdtrace_records.d" \
        "$testdir/syscall_fixture" "$testdir/$mode" \
        "$workload_uid" "$workload_gid" "$mode" \
        >"$testdir/$mode/records.tsv" 2>"$testdir/$mode/stderr"
    printf '%s\n' "$?" >"$testdir/$mode/exit-status"
done

mkdir -m 700 "$testdir/startup" || exit 1
printf 'this is not a valid D program;\n' >"$testdir/invalid.d"
doas "$testdir/libdtrace_consumer" "$testdir/invalid.d" \
    "$testdir/syscall_fixture" "$testdir/startup" \
    "$workload_uid" "$workload_gid" normal \
    >"$testdir/startup/records.tsv" 2>"$testdir/startup/stderr"
printf '%s\n' "$?" >"$testdir/startup/exit-status"
```

Expected command statuses are 0 for `normal`, nonzero for the other three cases.
Retrieve the four case directories to the development machine. Run the verifier
alongside [SMOKE.md](SMOKE.md), which contains the independent workload checks:

```sh
python3 tests/freebsd/verify_libdtrace.py /path/to/retrieved/results UID GID
```

The consumer checks that `/dev/dtrace/dtrace` already exists; it does not load
modules itself. No CMake, Ninja, Python-on-VM, or package installation is needed.
The consumer creates an `api-status.tsv` per case and assigns it to the supplied
ordinary identity so results can be retrieved. The fixture output is opened by
the child after dropping privileges. Compile-time errors are startup diagnostics,
not runtime error-handler callbacks.

After retrieving results, confirm no consumer or fixture process remains for
this test directory and remove only that exact directory. Preserve user-loaded
modules.

## Limits and next decisions

This fixed test schema does not define a public format or a general syscall
decoder. It does not establish sustained throughput, recovery after drops,
invalid-pointer recovery, clock alignment with userspace, arbitrary targets,
restart/non-returning behavior, stacks, replay, Linux compatibility, or package
readiness. The earlier `Private` probe-stability observation still applies.

See the [standalone workload](SMOKE.md) and the
[validation summary](../../docs/freebsd/VALIDATION.md) for the tested scope.

The [clock/signal experiment](CLOCK_SIGNAL.md) extends this
consumer with three additional modes and four cancellation status fields. The
original four cases require those new counters to be zero. Their typed D program
and workload remain unchanged; rerun this suite whenever the consumer changes.
