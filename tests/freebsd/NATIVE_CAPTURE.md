# Reusable native capture controller

[native_capture.h](../../src/tracer/freebsd/native_capture.h) and
[implementation](../../src/tracer/freebsd/native_capture.cpp) compose the reviewed
generator, session and decoder. The controller accepts one native PID and the
initial operation whitelist, supplies its own `getpid()` for monitor exclusion,
and returns owned typed events/notices and report snapshots. This three-operation
controller supports the diagnostic tool; the full application uses a separate
capture layer for the complete native catalog.

## API and lifecycle

`Start(configuration)` returns false with a terminal failure report on invalid
configuration or native startup failure. Otherwise the controller enters Running.
It is single-use: construct a fresh instance for another capture. Generation and
decoder/session limits retain the previously documented coverage and bounds.

`RequestStop(Completed)` records an ordinary completion request.
`RequestStop(Cancelled)` records explicit cancellation; later completion requests
do not erase that evidence. `Poll()` performs stop, continued consumption, close
and final decoding. Process the events/notices in the terminal update **before**
breaking the loop. Subsequent terminal polls return empty finished updates.

Runtime faults, drops and decoder failures automatically request failure stop.
The next poll stops/drains; fatal transport failure closes/finalizes immediately.
Check the final report, not merely the transport's drained flag. A completed stop
with unresolved calls becomes Failure. Explicit cancellation leaves unresolved
observed entries Cancelled, with ordinary duration/result/errno absent. Already
completed observations remain Completed. No target outcome is inferred from the
capture-stop reason.

| Phase | Allowed use |
| --- | --- |
| Ready | Start or Close; polling/stopping before start throws. |
| Running/Stopping | Poll, request Completed/Cancelled stop, or abandon with Close. |
| Finished | Empty terminal Poll, idempotent Close, valid stop requests ignored without relabelling the final result. |
| Closed | Empty terminal Poll/idempotent Close; an unfinished capture was abandoned, not finalized successfully. |

Close/destruction stop and close tracing resources without delivering pending
data. They cannot replace final drainage. Start/Poll allocation exceptions close
resources before propagating; discard that instance. `Report()` returns an owned
copy and can allocate/throw without changing capture state; the caller must close/
discard the instance on allocation failure. Lifecycle misuse throws `logic_error`;
unsupported stop reasons throw `invalid_argument`.

All methods are synchronous and must be serialized, including with other libdtrace
components. Methods are not signal-safe: handlers should only set a flag for the
ordinary polling loop. Do not fork an active controller. Library-call latency is
not hard-bounded by a caller's between-call deadline. There are no controller
worker threads, persistence format changes or output callbacks to reenter it.

The controller never starts/signals/kills target processes, installs signal
handlers, loads modules, checks target lifetime/PID reuse or follows descendants.
It does not define general syscall/ABI/argument coverage or recovery. Those
policies remain separate from this initial fail-and-stop capture composition.

## Reproduce the native validation

Preserve repository-relative paths in a fresh mode-0700 VM directory (`testdir`).
Copy the controller, generator, session and decoder pairs, the new unit/runtime
tests and controlled fixture, both existing workload fixtures, and existing
generator/decoder unit tests. Use the installed compiler, existing modules and
authorized `doas` method; no packages need installation.

```sh
mkdir -m 700 "$testdir/results" || exit 1
resultdir="$testdir/results"
for source in native_capture native_program native_event_decoder dtrace_session; do
    c++ -std=c++17 -Wall -Wextra -Werror -O0 -g -c \
        "$testdir/src/tracer/freebsd/$source.cpp" -o "$testdir/$source.o" \
        >"$resultdir/$source-build.stdout" 2>"$resultdir/$source-build.stderr" || exit 1
done
c++ -std=c++17 -Wall -Wextra -Werror -O0 -g "$testdir/tests/freebsd/test_native_capture.cpp" \
    "$testdir/native_capture.o" "$testdir/native_program.o" "$testdir/native_event_decoder.o" \
    "$testdir/dtrace_session.o" -o "$testdir/test_native_capture" -ldtrace \
    >"$resultdir/unit-build.stdout" 2>"$resultdir/unit-build.stderr" || exit 1
c++ -std=c++17 -Wall -Wextra -Werror -O0 -g "$testdir/tests/freebsd/test_native_capture_runtime.cpp" \
    "$testdir/native_capture.o" "$testdir/native_program.o" "$testdir/native_event_decoder.o" \
    "$testdir/dtrace_session.o" -o "$testdir/test_native_capture_runtime" \
    -Wl,--wrap=dtrace_open,--wrap=dtrace_close,--wrap=dtrace_stop,--wrap=dtrace_go,--wrap=dtrace_program_exec,--wrap=dtrace_program_strcompile,--wrap=dtrace_work \
    -ldtrace >"$resultdir/runtime-build.stdout" 2>"$resultdir/runtime-build.stderr" || exit 1
for source in controlled_capture_fixture unmarked_syscall_fixture syscall_fixture; do
    cc -std=c11 -Wall -Wextra -Werror -O0 -g -pthread "$testdir/tests/freebsd/$source.c" \
        -o "$testdir/$source" >"$resultdir/$source-build.stdout" 2>"$resultdir/$source-build.stderr" || exit 1
done
```

Also build/run the existing generator (19 checks) and decoder (64 checks) unit
executables using [NATIVE_PROGRAM.md](NATIVE_PROGRAM.md); retain their build logs
as `program-unit-build.*` and `decoder-unit-build.*`. Run all three units and
retain output/status as `native_capture-unit.*`, `native_program-unit.*` and
`native_event_decoder-unit.*`. The controller unit requires no successful tracing
open and runs as the ordinary user. Then run:

```sh
for profile in normal self cancel sigint sigterm incomplete fault drop limit capacity abandon option compile enable go work stop denied; do
    mkdir -m 700 "$resultdir/$profile" || exit 1
    fixture="$testdir/unmarked_syscall_fixture"
    case "$profile" in
        cancel|sigint|sigterm|incomplete|fault) fixture="$testdir/controlled_capture_fixture";;
        drop|capacity) fixture="$testdir/syscall_fixture";;
    esac
    privilege=doas
    if [ "$profile" = denied ]; then privilege=; fi
    $privilege "$testdir/test_native_capture_runtime" "$fixture" "$resultdir/$profile" \
        "$(id -u)" "$(id -g)" "$profile" >"$resultdir/$profile/records.tsv" \
        2>"$resultdir/$profile/stderr"
    printf '%s\n' "$?" >"$resultdir/$profile/exit-status"
done
```

Harness statuses should be zero when expected success/failure assertions hold.
The test executable alone owns child creation, signals and failure cleanup.
Controlled targets wait on a parent pipe; after capture stops, they must still
be alive and complete the read successfully when released. Test-only link wrappers
observe copied raw records/count real handle calls and inject compile/enable/go/
work/stop failures. None of those modes exist in the production controller.
Option failure, copy/correlation limits, runtime invalid-pointer fault and kernel
buffer drops are actual exercised mechanisms. Zero drops leave that case
unverified. Ordinary-user denial must be reported unverified if access is granted
elsewhere; do not change privileges to force an outcome.

Retrieve evidence and run locally:

```sh
python3 tests/freebsd/verify_native_capture.py /path/to/results UID GID
```

Record hashes/environment, verify no test process remains and remove only the
exact private VM directory. Preserve modules and unrelated state.
