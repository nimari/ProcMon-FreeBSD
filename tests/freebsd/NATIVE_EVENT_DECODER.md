# Typed native events and streaming correlation

[native_event_decoder.h](../../src/tracer/freebsd/native_event_decoder.h) and
[implementation](../../src/tracer/freebsd/native_event_decoder.cpp) consume owned
session batches in the reviewed v1 layout of [session_records.d](session_records.d).
The implementation targets FreeBSD amd64; the public header uses standard C++17
types. These tests exercise the diagnostic record format independently of the application.

## Contract

The supported operations are `openat`, `read` and `write`. BEGIN/END carry the
target PID and raw DTrace `timestamp`; fixture getpgid/exit controls are recognized
without becoming syscall events. Other providers, ABIs, operations, action kinds
or field layouts produce explicit issues. This is not a general D-source decoder.
Clock-domain provenance depends on the reviewed producer/schema; identical-shaped
integers from arbitrary D programs cannot attest their clock domain themselves.

Pairing uses PID/TID/operation/raw start, independently of CPU or arrival order.
Return-first delivery and END preceding another CPU's data are supported.
Completed pairs stream once BEGIN is known. Default state bounds are 4,096 pending
keys and 4,096 recent completed keys; capacity exhaustion fails explicitly.
The recent-key cache detects recent duplicates only, not arbitrary replay. There
is no session-long accumulation of completed events inside the decoder.

Events own their data. `correlationStartNs` retains the raw pairing token even for
orphan returns; it does not assert an observed entry. Entry presence, raw entry
time, relative timestamp, ordinary duration/result/errno, CPU observations and
raw return diagnostics are separate fields. Relative time is checked subtraction
from raw BEGIN. Durations are checked against overflow and known session bounds;
END validates the final clock range, including previously streamed observations.

- An observed pair with a representable nonnegative 32-bit errno lane completes.
  Negative successful result values remain negative successes when errno is zero.
- Unresolved entries become cancelled only on explicit cancellation evidence at
  Finish. Missing entries remain incomplete; no entry/time is invented.
- Invalid/sentinel return bits remain diagnostic. Ordinary duration/result/errno
  optionals stay absent for cancelled/incomplete records.
- Structurally valid completed calls stay completed when cancellation or loss
  occurs elsewhere. The final capture report remains incomplete in those cases.

Only descriptor, third argument and bounded openat path are captured by this
initial schema. Buffer pointers/contents, openat mode and general argument schemas
remain outside it. A 64-byte path sets `atCaptureLimit`, not proof of truncation.
Read/write path slots must contain the reviewed `-` placeholder. Entries/returns
must agree on copied arguments. The errno check is a lane-range check, not proof
that every representable number is an assigned FreeBSD errno.

Call `Consume` for every batch, including Done/notices. After session Stop, final
drain and Close, call `Finish(status, cancellationRequested)`. Final checks include
transport lifecycle, delivered record/counter totals, boundaries, errors/drops,
and unresolved observations. Check the final report before declaring a capture
complete; later END/loss failures cannot retract already emitted events. Allocation
exceptions require discarding the decoder instance. Post-Finish misuse throws.
This is an internal event model, not an application/database/trace-format change.

## Reproduce

Preserve repository-relative paths in a fresh mode-0700 VM directory. Copy both
session and decoder components, [test_native_event_decoder.cpp](test_native_event_decoder.cpp),
the extended [session harness](test_dtrace_session.cpp), both original fixtures,
and all three D programs used below. Set `testdir` to the exact private directory.

First build/run the default session suite from [DTRACE_SESSION.md](DTRACE_SESSION.md)
against the extended harness, retaining its nine result directories and four
build logs under `results`. Its default build needs no decoder source or flag.
Keep the session object as `$testdir/dtrace_session.o`. Add these checks:

```sh
resultdir="$testdir/results"
c++ -std=c++17 -Wall -Wextra -Werror -O0 -g -c \
    "$testdir/src/tracer/freebsd/native_event_decoder.cpp" -o "$testdir/native_event_decoder.o" \
    >"$resultdir/decoder-build.stdout" 2>"$resultdir/decoder-build.stderr" || exit 1
c++ -std=c++17 -Wall -Wextra -Werror -O0 -g \
    "$testdir/tests/freebsd/test_native_event_decoder.cpp" "$testdir/native_event_decoder.o" \
    -o "$testdir/test_native_event_decoder" \
    >"$resultdir/unit-build.stdout" 2>"$resultdir/unit-build.stderr" || exit 1
"$testdir/test_native_event_decoder" >"$resultdir/unit.stdout" 2>"$resultdir/unit.stderr"
printf '%s\n' "$?" >"$resultdir/unit.status"
c++ -std=c++17 -Wall -Wextra -Werror -O0 -g -DPROCMON_TEST_NATIVE_DECODER \
    "$testdir/tests/freebsd/test_dtrace_session.cpp" "$testdir/dtrace_session.o" \
    "$testdir/native_event_decoder.o" -o "$testdir/test_decoder_capture" \
    -Wl,--wrap=dtrace_open,--wrap=dtrace_close,--wrap=dtrace_stop -ldtrace \
    >"$resultdir/capture-build.stdout" 2>"$resultdir/capture-build.stderr" || exit 1
for mode in normal sigint sigterm drop; do
    mkdir -m 700 "$resultdir/decoded-$mode" || exit 1
    fixture="$testdir/syscall_fixture"
    if [ "$mode" = sigint ] || [ "$mode" = sigterm ]; then
        fixture="$testdir/clock_signal_fixture"
    fi
    doas "$testdir/test_decoder_capture" "$testdir/tests/freebsd/session_records.d" \
        "$fixture" "$resultdir/decoded-$mode" "$(id -u)" "$(id -g)" "$mode" --decode \
        >"$resultdir/decoded-$mode/records.tsv" 2>"$resultdir/decoded-$mode/stderr"
    printf '%s\n' "$?" >"$resultdir/decoded-$mode/exit-status"
done
```

All harness statuses should be zero when their assertions hold. In decoder drop
mode, macro `$2` is zero to retain the normal schema; pressure comes from the
session's one-KiB buffer and delayed consumption. The default old drop mode still
uses its original D program/macro. Zero actual drops leave the pressure case
unverified, not passed. No packages, module or privilege-policy changes are needed.

Retrieve results and run:

```sh
python3 tests/freebsd/verify_native_event_decoder.py /path/to/results UID GID
```

This also invokes the unchanged session verifier for all nine default regressions.
The new checker compares typed events to independently rendered owned raw records,
raw BEGIN/END clock references, fixture results and argument/path data. Native
unit checks exercise missing/orphaned/duplicate data, bounds, unsupported inputs
and streaming with one pending slot/one recent-key slot. Record input hashes and
environment, verify no test process remains, then remove only the exact private
VM directory. Preserve modules and unrelated state.
