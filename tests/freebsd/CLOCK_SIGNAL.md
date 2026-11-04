# Clock alignment and controlled signal shutdown

These checks exercise the standalone libdtrace test consumer and preserve the
original smoke workload/scripts. The four earlier API
cases must be rerun after rebuilding the extended consumer.

## Clock experiment

[clock_signal_fixture.c](clock_signal_fixture.c) brackets eight `getpgid` calls
with `CLOCK_MONOTONIC` reads. Unique nonexistent PID arguments identify the calls
without relying on per-CPU output order. The calls' userspace results/errno are
compared with their captured return records. The fixture pins only its own
process, alternating between up to two allowed CPUs, then restores its mask.

[clock_signal_records.d](clock_signal_records.d) records each entry/return
`timestamp`. The consumer reports the origin CPU from the library's probe data.
The verifier requires complete matching records, positive/bracket-consistent
intervals, matching CPUs, and monotonic sample sequences.

For each userspace bracket `[before, after]` and kernel timestamps `[entry,
return]`, a possible constant offset `kernel - userspace` lies in:

```text
[return - after, entry - before]
```

The intersection across samples is classified as `DIRECT` when it contains zero,
`OFFSET_REQUIRED` when it excludes zero but is nonempty, and `NO_CONSTANT_OFFSET`
when no single offset fits all samples. A nonzero offset is an experimental
finding, not an excuse to loosen record checks or silently alter timestamps.
No conversion is applied to these raw records or to ProcMon. A constant offset
observed over this short test does not establish long-term drift or suspend/
resume behavior. Installed kernel source and measured evidence must inform a
separately reviewed production clock policy.

## Controlled signal experiment

In `sigint` and `sigterm` modes, the unprivileged fixture emits its identity,
marks readiness, and enters a read on its own empty pipe while keeping the write
end open. After the consumer has received that read's entry record, it sends the
selected real POSIX signal to itself using `kill(getpid(), signal)`. The existing
signal handler only sets a flag; the main loop performs cleanup.

The verifier requires observed sent/received signal numbers, conventional
consumer exit status (`128 + signal`), one blocked target read, final END data,
and successful stop/drain/close/reap within two seconds of signal dispatch.
The consumer kills only its own fixture during cleanup. A read in flight at
cancellation may have no return record; it is not fabricated into a complete
syscall. These cases exercise actual handlers and cleanup at a controlled point,
not external-terminal/process-group delivery or signals inside every library
call. They do not authorize killing arbitrary monitored processes in a backend.

The return diagnostic preserves the raw 64-bit error lane. The inspected target
emitted all-one bits (signed `-1`) when the blocked read was killed. This is a
cancellation sentinel, not a normal positive errno to pass to `strerror` or an
ordinary completed event to persist. The test does not invent a return when the
kernel emits none.

## Reproduce

In a fresh mode-0700 VM temporary directory, copy the extended consumer, both
the old and new D programs, and both C fixtures. Build with the existing compiler:

```sh
cc -std=c11 -Wall -Wextra -Werror -O0 -g -pthread \
    "$testdir/syscall_fixture.c" -o "$testdir/syscall_fixture" || exit 1
cc -std=c11 -Wall -Wextra -Werror -O0 -g -pthread \
    "$testdir/clock_signal_fixture.c" -o "$testdir/clock_signal_fixture" || exit 1
cc -std=c11 -Wall -Wextra -Werror -O0 -g \
    "$testdir/libdtrace_consumer.c" -o "$testdir/libdtrace_consumer" -ldtrace || exit 1

for mode in clock sigint sigterm; do
    mkdir -m 700 "$testdir/$mode" || exit 1
    doas "$testdir/libdtrace_consumer" "$testdir/clock_signal_records.d" \
        "$testdir/clock_signal_fixture" "$testdir/$mode" \
        "$(id -u)" "$(id -g)" "$mode" \
        >"$testdir/$mode/records.tsv" 2>"$testdir/$mode/stderr"
    printf '%s\n' "$?" >"$testdir/$mode/exit-status"
done
```

Also run `normal`, `fault`, `drop`, and `startup` using the unchanged old D program
and workload as described in [LIBDTRACE.md](LIBDTRACE.md). The API status schema
now includes `blocked`, `signal_sent`, `signal_seen`, and `cancel_elapsed_ns`;
the updated previous-case verifier requires these to be zero for old cases.

Retrieve the case directories and verify locally:

```sh
python3 tests/freebsd/verify_clock_signal.py /path/to/results UID GID
python3 tests/freebsd/verify_libdtrace.py /path/to/results UID GID
```

No Python, packages, or CMake need to be installed on the VM. Confirm that no test
process remains, then remove only the exact private VM directory. Preserve
user-loaded modules, existing policy/boot settings, and unrelated work. All
source/clock/kernel behavior claims are limited to the tested target and cases.
