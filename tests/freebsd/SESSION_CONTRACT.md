# Experimental backend event and time contract

Scope: one isolated capture session, fixed native syscall probes, and bounded
fixture workloads. [event_contract.h](event_contract.h) is an experimental
in-memory model; it is not a ProcMon public API, database format, or file ABI.
Application sources, existing raw D programs, and original fixtures are unchanged.

## Contract version 1

- Session metadata identifies `freebsd-native`, contract version 1, and the
  `dtrace-session-ns` clock. Raw session start and end are both captured by
  DTrace's `timestamp` in BEGIN/END actions.
- Relative event time is `raw_entry - raw_session_start`, checked before
  subtraction. Raw values before the session or beyond its end are rejected.
  Neither userspace `CLOCK_MONOTONIC` nor the measured VM offset participates.
  Userspace monotonic time remains separate for the consumer's watchdog and
  cleanup measurements; it is not subtracted from captured event timestamps.
- PID, TID, operation, entry/return presence, state, and separate validity flags
  accompany values. Output order is not a global time-order guarantee.
- A paired return with nonnegative, representable errno is `completed`. Duration,
  raw result, and errno are valid; errno 0 denotes success. A negative successful
  result stays a successful result rather than becoming a Linux-style errno.
- An observed entry without a usable return becomes `cancelled` only when
  cancellation was actually requested. Duration/result/errno are invalid and
  their ordinary value fields are zero. Observed return diagnostics remain
  separately available, including the all-one error bits from killed reads.
- Missing data without that cancellation evidence is `incomplete`. A return
  without an observed entry does not invent an entry or a timestamp. Incomplete
  captures fail this bounded experiment rather than being reported complete.
- A valid ordinary return completed before cancellation remains `completed`.
  Cancelling the session does not relabel every previously completed call.

These states describe capture completeness. `cancelled` does not assert that a
monitored syscall itself failed or that the target stopped; an arbitrary tracee
may continue after capture ends. The fixture-killing cleanup policy is test-only.

This prototype does not claim that all nonnegative 32-bit values are defined
FreeBSD errnos; it only separates representable ordinary error lanes from invalid
negative/sentinel bits. Schema coverage and platform-specific decoding remain
separate work. Durations are bounded using subtraction to avoid addition overflow.

## Consumer and data ownership

The optional `--contract` flag on [libdtrace_consumer.c](libdtrace_consumer.c)
selects [session_records.d](session_records.d) and owned, fixed-width values.
The flag is supported only with `normal`, `sigint`, and `sigterm`. Legacy modes
without that flag keep their original raw output and are regression-tested.

The D program supplies matching per-thread start values in entry/return data.
A bounded 32-slot collector keys records by PID/TID/operation/start, accepting
either callback arrival order, checking duplicate records and argument agreement,
and failing on capacity exhaustion. It retains copied payloads, not library
callback pointers. Normalization/emission happens after the final drain, so both
session boundaries are known. It is a small test collector, not a production
queue or a system-wide event engine.

Output has raw records for independent comparison, one SESSION envelope, versioned
CONTRACT_EVENT rows, and CONTRACT_COUNTS. Each normalized row contains:

```text
tag version pid tid operation state timestamp_valid timestamp_ns
duration_valid duration_ns result_valid result errno_valid errno
entry_present return_present raw_result raw_errno_bits
```

Raw argument/path records remain separate; this version does not specify a
general argument encoding. One stream contains one session; multi-session IDs,
wall-clock mapping, persistence, and replay are not defined here.

## Reproduce

Copy the consumer, header, contract D program, portable unit check, both existing
fixtures, and existing D programs into a fresh private mode-0700 VM directory.
Use an ordinary `/bin/sh` and the existing compiler and authorized `doas` method:

```sh
cc -std=c11 -Wall -Wextra -Werror -O0 -g \
    "$testdir/test_event_contract.c" -o "$testdir/test_event_contract" || exit 1
"$testdir/test_event_contract" || exit 1
cc -std=c11 -Wall -Wextra -Werror -O0 -g -pthread \
    "$testdir/syscall_fixture.c" -o "$testdir/syscall_fixture" || exit 1
cc -std=c11 -Wall -Wextra -Werror -O0 -g -pthread \
    "$testdir/clock_signal_fixture.c" -o "$testdir/clock_signal_fixture" || exit 1
cc -std=c11 -Wall -Wextra -Werror -O0 -g \
    "$testdir/libdtrace_consumer.c" -o "$testdir/libdtrace_consumer" -ldtrace || exit 1
for mode in normal sigint sigterm; do
    mkdir -m 700 "$testdir/contract-$mode" || exit 1
    fixture="$testdir/clock_signal_fixture"
    if [ "$mode" = normal ]; then fixture="$testdir/syscall_fixture"; fi
    doas "$testdir/libdtrace_consumer" "$testdir/session_records.d" \
        "$fixture" "$testdir/contract-$mode" "$(id -u)" "$(id -g)" \
        "$mode" --contract >"$testdir/contract-$mode/records.tsv" \
        2>"$testdir/contract-$mode/stderr"
    printf '%s\n' "$?" >"$testdir/contract-$mode/exit-status"
done
```

Also rerun the seven previous raw cases from [LIBDTRACE.md](LIBDTRACE.md) and
[CLOCK_SIGNAL.md](CLOCK_SIGNAL.md), without `--contract`. Retrieve the ten result
directories and verify locally:

```sh
python3 tests/freebsd/verify_session_contract.py /path/to/results UID GID
python3 tests/freebsd/verify_libdtrace.py /path/to/results UID GID
python3 tests/freebsd/verify_clock_signal.py /path/to/results UID GID
```

The portable [test_event_contract.c](test_event_contract.c) checks valid negative
results, ordinary errors, cancelled/missing/orphaned records, invalid clock/
version/session bounds, pre-session timestamps, and overflow-safe durations. It
can also be compiled on the development Mac without FreeBSD libraries.

After retrieving evidence, verify no experiment process remains and remove only
the exact private VM directory. Preserve user-loaded modules and all boot/policy
settings. No CMake or package installation is needed. The earlier fixture-owned
process-killing policy is test-only; it is not proposed for arbitrary monitored
processes. Long-term clock drift, external signal delivery, stacks, schemas,
loss recovery, application adapters, and persistence remain outside this increment.
