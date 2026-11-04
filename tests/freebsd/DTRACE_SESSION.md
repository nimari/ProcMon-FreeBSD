# Reusable FreeBSD DTrace session

[dtrace_session.h](../../src/tracer/freebsd/dtrace_session.h) and
[dtrace_session.cpp](../../src/tracer/freebsd/dtrace_session.cpp) implement a
synchronous, single-use tracing session on FreeBSD amd64. Both the diagnostic
tool and native application use this component;
the tests below exercise its session API independently.

## Lifecycle and ownership

`Start(program, arguments, options)` checks for the existing character device,
opens the library, registers handlers, sets options, compiles trusted D source,
enables it and starts tracing. Arguments map to `$1`, `$2`, etc.; the component
supplies `$0`. Startup failure records a diagnostic and closes immediately.
The component does not create/kill processes, enforce a filtering policy, load
modules, execute commands, install signal handlers, or interpret syscall fields.
Filtering belongs to the caller's reviewed D program.

`Poll()` returns owned batches of probe identities, CPU IDs, record descriptors'
action/argument/alignment fields, copied payloads, and copied runtime-error/drop
notices. Assignment descriptors retain empty byte arrays. Descriptor counts and
payload bounds are checked before copying. The record callback suppresses library
formatting. No library pointer or borrowed payload escapes a callback.

Finish explicitly with `Stop()`, then `Poll()` until `Done`, then `Close()`.
Successful stop is idempotent; polling a drained open session returns an empty
`Done` batch. Close is idempotent. Close/destruction stop and close resources
without delivering unconsumed data; an undrained started session sets `discarded`.
Destruction is cleanup, not a substitute for final-drain delivery.

`SessionStatus.failed` describes fatal transport/API/copy failure. A runtime D
fault or kernel buffer drop is separately counted and delivered as a notice;
**neither `failed=false` nor `drained=true` proves complete capture**. Callers must
inspect error/drop counters, notices and discarded status before declaring a
capture complete. Notice detail is a native fault/drop kind, not a tracee errno.
No production recovery/queue/persistence policy is selected here.

Default per-batch limits are 16 MiB of copied text/payload, 16,384 probes,
131,072 records and 1,024 notices. Allocation/container overhead is additional
and bounded by cardinality. Limit exhaustion aborts copying, reports fatal
failure and prevents a successful-drain claim. Only the byte-limit failure was
forced in this native suite. It is not a kernel drop and does not increment the
kernel drop count. C++ exceptions are contained within C callbacks; allocation
failures may propagate from the C++ method after closure.

Serialize calls, including calls to other libdtrace components. Methods are not
signal-safe. The caller may set a signal flag and perform normal cleanup later.
No guarantee is made that every synchronous library call is interruptible or
bounded by a caller's polling-loop deadline. Raw numeric fields and bytes are
internal native transport data, not a persisted or portable record ABI.

## Reproduce the native tests

Copy the two component files, [test_dtrace_session.cpp](test_dtrace_session.cpp),
both existing fixtures and both existing D programs into a fresh private
mode-0700 VM directory, preserving `src/tracer/freebsd/` and `tests/freebsd/`.
Set `testdir` to its exact path; use ordinary `/bin/sh`, the installed compiler,
already-loaded modules, and authorized `doas` access:

```sh
mkdir -m 700 "$testdir/results" || exit 1
resultdir="$testdir/results"
c++ -std=c++17 -Wall -Wextra -Werror -O0 -g -c \
    "$testdir/src/tracer/freebsd/dtrace_session.cpp" -o "$testdir/dtrace_session.o" \
    >"$resultdir/component-build.stdout" 2>"$resultdir/component-build.stderr" || exit 1
c++ -std=c++17 -Wall -Wextra -Werror -O0 -g \
    "$testdir/tests/freebsd/test_dtrace_session.cpp" "$testdir/dtrace_session.o" \
    -o "$testdir/test_dtrace_session" -Wl,--wrap=dtrace_open,--wrap=dtrace_close,--wrap=dtrace_stop \
    -ldtrace >"$resultdir/test-build.stdout" 2>"$resultdir/test-build.stderr" || exit 1
cc -std=c11 -Wall -Wextra -Werror -O0 -g -pthread \
    "$testdir/tests/freebsd/syscall_fixture.c" -o "$testdir/syscall_fixture" \
    >"$resultdir/fixture-build.stdout" 2>"$resultdir/fixture-build.stderr" || exit 1
cc -std=c11 -Wall -Wextra -Werror -O0 -g -pthread \
    "$testdir/tests/freebsd/clock_signal_fixture.c" -o "$testdir/clock_signal_fixture" \
    >"$resultdir/signal-build.stdout" 2>"$resultdir/signal-build.stderr" || exit 1
for mode in normal fault drop startup limit abandon sigint sigterm denied; do
    mkdir -m 700 "$resultdir/$mode" || exit 1
    script="$testdir/tests/freebsd/libdtrace_records.d"
    fixture="$testdir/syscall_fixture"
    if [ "$mode" = sigint ] || [ "$mode" = sigterm ]; then
        script="$testdir/tests/freebsd/clock_signal_records.d"
        fixture="$testdir/clock_signal_fixture"
    fi
    privilege=doas
    if [ "$mode" = denied ]; then privilege=; fi
    $privilege "$testdir/test_dtrace_session" "$script" "$fixture" \
        "$resultdir/$mode" "$(id -u)" "$(id -g)" "$mode" \
        >"$resultdir/$mode/records.tsv" 2>"$resultdir/$mode/stderr"
    printf '%s\n' "$?" >"$resultdir/$mode/exit-status"
done
```

All harness statuses should be zero, including successful assertions of failure
behavior. `fault` uses actual `copyinstr(0)` errors; `drop` withholds consumption
with a 1 KiB buffer. A zero drop count leaves that profile unverified, not passed.
`startup` supplies invalid D, `limit` sets a one-byte copy budget, and `abandon`
closes a started session before consuming. `denied` expects an ordinary identity
without DTrace access; do not change permissions to force that result elsewhere.

Normal runs twice with separate fixture processes/new session objects in the same
parent process, then checks active-destructor stop/close. Test-only linker
wrappers count real calls without changing behavior. The harness gates and drops
privileges in its own child before release; signal tests self-deliver SIGINT or
SIGTERM after observing the fixture read. Only the harness-owned child is killed
during cleanup. That policy is not part of the component or proposed for arbitrary
targets. All batches are decoded after library closure to check ownership.

Retrieve evidence and run locally:

```sh
python3 tests/freebsd/verify_dtrace_session.py /path/to/results UID GID
```

The verifier reuses the independent workload comparison for both normal rounds
and checks all nine profiles. Record source hashes/environment. Verify no test
process remains, remove only the exact private VM directory and preserve modules
and unrelated state. Reverting the increment removes the unselected component,
tests and corresponding documentation changes without affecting application code.
