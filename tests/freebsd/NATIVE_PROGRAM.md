# PID/syscall-filtered native program generation

[native_program.h](../../src/tracer/freebsd/native_program.h) and
[implementation](../../src/tracer/freebsd/native_program.cpp) generate reviewed D
source for one native PID and a nonempty selection of openat/read/write. Generation
has no tracing/process side effects and uses standard C++17 only. The generated
program is executed through the existing FreeBSD session/decoder components.

## Rules and limits

The caller supplies the actual monitor PID. Both PIDs must be positive native
32-bit values; invalid values, empty filters and unsupported enum values throw
`invalid_argument`. Operations are sorted/deduplicated. Names come from a fixed
whitelist; PID text uses locale-independent decimal formatting. There is no
implicit all-process option, arbitrary expression/name interpolation or macro
argument requirement. Generation does not check process identity/lifetime.

Every entry and return predicate restricts `pid == target` and `pid != monitor`.
Selecting the monitor itself is allowed but yields no syscall events. Only
`syscall:freebsd` probes are generated; child PIDs/other ABIs are not followed.
There are no getpgid controls, active flags or fixture-marker dependencies.
Tracing covers selected calls from session go until stop, not only the fixture's
recorded workload. Other target I/O can therefore appear legitimately.

State is thread-local and separate for each operation. Entry clears its seen
flag before argument copying and sets it only after those steps succeed. Return
requires that flag, emits values, then clears the state. Calls whose entries were
not observed, such as calls already in flight at attachment, have no generated
return record. This does not establish arbitrary restart/nested-call behavior,
drop/fault recovery, PID-reuse protection or process lifecycle supervision.

The payload matches the v1 native decoder layout: raw DTrace BEGIN/END timestamps,
five entry scalars plus a 65-byte string slot, and eight return scalars plus the
same slot. Only descriptor, third scalar and bounded openat path are captured;
buffer pointers/contents and openat mode remain outside this initial coverage.
Fault/drop notices and the decoder's final report still determine capture quality.

## Native test reproduction

Copy both new generator files, the existing session/decoder files, both new C++
tests, [unmarked_syscall_fixture.c](unmarked_syscall_fixture.c), the unchanged
[syscall_fixture.c](syscall_fixture.c) and
[decoder unit test](test_native_event_decoder.cpp) to a fresh mode-0700 VM
directory. Preserve repository-relative paths and set `testdir` to that exact
directory. Use ordinary `/bin/sh`, installed compiler, existing modules and `doas`.

```sh
mkdir -m 700 "$testdir/results" || exit 1
resultdir="$testdir/results"
for item in program decoder session; do
    case "$item" in
        program) source=native_program;;
        decoder) source=native_event_decoder;;
        session) source=dtrace_session;;
    esac
    c++ -std=c++17 -Wall -Wextra -Werror -O0 -g -c \
        "$testdir/src/tracer/freebsd/$source.cpp" -o "$testdir/$source.o" \
        >"$resultdir/$item-build.stdout" 2>"$resultdir/$item-build.stderr" || exit 1
done
c++ -std=c++17 -Wall -Wextra -Werror -O0 -g \
    "$testdir/tests/freebsd/test_native_program.cpp" "$testdir/native_program.o" \
    -o "$testdir/test_native_program" >"$resultdir/unit-build.stdout" 2>"$resultdir/unit-build.stderr" || exit 1
c++ -std=c++17 -Wall -Wextra -Werror -O0 -g \
    "$testdir/tests/freebsd/test_native_program_capture.cpp" "$testdir/native_program.o" \
    "$testdir/native_event_decoder.o" "$testdir/dtrace_session.o" -o "$testdir/test_native_program_capture" \
    -ldtrace >"$resultdir/capture-build.stdout" 2>"$resultdir/capture-build.stderr" || exit 1
for item in fixture unmarked; do
    source=syscall_fixture
    if [ "$item" = unmarked ]; then source=unmarked_syscall_fixture; fi
    cc -std=c11 -Wall -Wextra -Werror -O0 -g -pthread \
        "$testdir/tests/freebsd/$source.c" -o "$testdir/$source" \
        >"$resultdir/$item-build.stdout" 2>"$resultdir/$item-build.stderr" || exit 1
done
c++ -std=c++17 -Wall -Wextra -Werror -O0 -g \
    "$testdir/tests/freebsd/test_native_event_decoder.cpp" "$testdir/native_event_decoder.o" \
    -o "$testdir/test_native_event_decoder" >"$resultdir/decoder-unit-build.stdout" \
    2>"$resultdir/decoder-unit-build.stderr" || exit 1
"$testdir/test_native_program" >"$resultdir/unit.stdout" 2>"$resultdir/unit.stderr"
printf '%s\n' "$?" >"$resultdir/unit.status"
"$testdir/test_native_event_decoder" >"$resultdir/decoder-unit.stdout" 2>"$resultdir/decoder-unit.stderr"
printf '%s\n' "$?" >"$resultdir/decoder-unit.status"
for profile in all openat read write openat-read openat-write read-write unmarked self; do
    mkdir -m 700 "$resultdir/$profile" || exit 1
    fixture="$testdir/syscall_fixture"
    if [ "$profile" = unmarked ]; then fixture="$testdir/unmarked_syscall_fixture"; fi
    doas "$testdir/test_native_program_capture" "$fixture" "$resultdir/$profile" \
        "$(id -u)" "$(id -g)" "$profile" >"$resultdir/$profile/records.tsv" \
        2>"$resultdir/$profile/stderr"
    printf '%s\n' "$?" >"$resultdir/$profile/exit-status"
done
```

All harness statuses should be zero. Each profile runs two gated unprivileged
fixtures, one selected and one noise process, and exercises six monitor I/O calls
while capture is active. Self mode selects the monitor and leaves both children
unselected. The new fixture contains six independently checked calls and no marker
calls; the original fixture remains unchanged. Only test code owns/reaps/kills its
children on failure; the production generator manages no processes.

Retrieve results and verify locally:

```sh
python3 tests/freebsd/verify_native_program.py /path/to/results UID GID
```

The checker validates all captured raw/typed pairs, source predicates, selected
operations, PID/TID exclusion, clocks/arguments/results and workload-oracle subsets.
It permits additional target I/O outside the oracle instead of falsely requiring
exactly 16/6 total events. Record source hashes/environment, check no test process
remains, and remove only the exact private VM directory after retrieving evidence.
Preserve modules and unrelated state.
