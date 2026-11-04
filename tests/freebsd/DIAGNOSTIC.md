# FreeBSD headless diagnostic pilot

This standalone, three-syscall FreeBSD/amd64 diagnostic exercises the
[capture controller](../../src/tracer/freebsd/native_capture.h) independently of
the full ProcMon application. Its build has no install target.

See [target validation and lifetime](TARGET_LIFETIME.md) for the current complete
runtime suite, identity guards and automatic exit handling.

## Build and use on FreeBSD

From the repository root on FreeBSD amd64, with the base C++17 compiler, BSD make,
DTrace headers/library, loaded syscall provider and appropriate tracing privileges:

```sh
repo=$(pwd)
testdir=$(mktemp -d /tmp/procmon-diagnostic.XXXXXX)
make -f "$repo/src/tracer/freebsd/diagnostic/Makefile" BUILD_DIR="$testdir/build"
"$testdir/build/procmon-freebsd-capture" --help
doas "$testdir/build/procmon-freebsd-capture" --pid 1234 --events openat,read,write --duration-ms 1000
```

Replace 1234 with the native FreeBSD process to observe. Without `--duration-ms`,
capture continues until target exit or SIGINT/SIGTERM. The optional duration is 1..86400000 ms
measured with the userspace steady clock after tracing starts; it is a best-effort
stop deadline, not an event timestamp origin or an exact sampling window. The
actual observed window is the DTrace BEGIN/END interval in the final summary.
Only one positive PID in the signed native PID range is accepted. All three
operations are selected by default; `--events` accepts a nonempty comma-separated
subset and deduplicates names. Unsupported/repeated options, missing values and
invalid integers fail before any tracing is opened. `--help` is standalone.

The build recipe is separate from the root build and uses `-std=c++17`, warnings
as errors, `-pthread` and `-ldtrace`. It recompiles the small standalone executable
when one of its source/header dependencies changes. Set an absolute `BUILD_DIR`
outside the checkout to keep build artifacts separate. Paths used with this
simple BSD make recipe should have no whitespace. No packages/modules are
installed or loaded by the driver or recipe.

## Output and termination contract

Stdout is ASCII JSON Lines with schema `procmon-freebsd-diagnostic`, version 1.
Successful startup emits one `ready` record with actual monitor/target PID,
selected operations, duration, platform, byte-string encoding and clock. `event`
records retain the controller's typed fields, signed descriptors/results, wide
counts, correlation token, entry/return evidence, CPU, optional timestamps,
duration, errno, bounded path and raw return diagnostics. `notice` records retain
runtime faults/drops and their counts. A final `summary` contains capture reason,
quality, signal, diagnostics, full session status and decoder counts/boundaries/
issue. Startup failure emits only a failure summary and a stderr diagnostic.
Ready and summary now also include target ABI/identity validation, boot-relative
start values, raw target exit status when observed and stop cause. The kernel
process address used internally by probe guards is never emitted.

Strings represent bytes as JSON code points 0..255: quotes/backslashes are
escaped, and control/non-ASCII bytes use `\u00XX`. Recover original bytes by
mapping each decoded code point to its byte, e.g. Python `value.encode('latin1')`.
This preserves non-UTF-8 filenames and is not a claim about their text encoding.
Use a JSON reader that preserves 64-bit integers; ordinary JavaScript Number
cannot represent all clock/counter values exactly. Missing values are JSON null,
and flags are JSON booleans. Paths contain at most 64 captured bytes; reaching
that limit does not prove truncation. Read/write buffer contents/pointers and
openat mode are outside this schema. This pilot format is not a persisted
ProcMon trace/replay format or a promised stable public API.

Streamed observations remain provisional until final quality is known. SIGINT
and SIGTERM handlers only set a `sig_atomic_t` flag; the main loop requests
cancellation, polls through drainage, emits final-batch events/notices and closes
the session before the summary. Unresolved observed entries become Cancelled,
with no invented result/errno/duration. Cancellation always has `complete:false`.
Runtime errors/loss remain Failure even if a signal is also received. An ordinary
duration stop requires complete decoder/session evidence to succeed; unresolved
entries instead produce Failure. A broken output stream ignores SIGPIPE, detects
the write failure, abandons any unfinished capture through RAII cleanup and
reports stderr; no delivered final summary can be promised on an unusable stream.

| Exit | Meaning |
| --- | --- |
| 0 | Help, or a complete duration/target-exit capture. |
| 1 | Capture/startup/formatting/output failure or incomplete timed capture. |
| 2 | Invalid command line. |
| 130 / 143 | Drained SIGINT / SIGTERM cancellation. |

The pilot never spawns, signals or kills the target. It now rejects missing,
zombie, kernel and unsupported-ABI targets before tracing, binds probes to the
inspected process identity and stops on exit. Any subsequent exec or watcher
failure ends capture as Failure. Nonzero/signalled target exit can still yield
complete capture when all observed calls have valid returns; target exit status
is reported separately. Empty successful capture does not prove selected calls
occurred. The current [lifetime policy](TARGET_LIFETIME.md) records race handling,
kernel-token/CTF dependencies and the limits of the controlled reuse tests.
SIGKILL of the monitor, crashes and power failure cannot drain capture. Signal
latency and sustained-load performance are not established here.

## Reproduce the current checks

Use [TARGET_LIFETIME.md](TARGET_LIFETIME.md) and `run_target_checks.sh` for the
current native runtime, guard, CLI and independent-oracle suite. It starts native
fixtures before attachment and verifies their identity through shutdown.

`test_diagnostic_runtime.cpp` and `verify_diagnostic.py` retain lower-level
fixtures and oracle helpers. Older standalone runtime profiles that exec after
attachment conflict with the current identity policy; they are not the current
acceptance suite.

Keep each run's evidence in a fresh directory. After preserving results, remove
only that exact private directory; do not unload modules or change system policy.
See the [validation summary](../../docs/freebsd/VALIDATION.md).
