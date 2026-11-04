# Reusable native syscall metadata component

The [header](../../src/tracer/freebsd/syscall_metadata.h) and
[implementation](../../src/tracer/freebsd/syscall_metadata.cpp) discover
`syscall:freebsd` metadata on FreeBSD amd64. The native application also uses
this component. The standalone checks below
require no module or policy changes.

`DiscoverNativeSyscallMetadata()` returns an owned `MetadataSnapshot`. Probe and
argument strings remain valid after handle closure. Variable-length vectors
retain every advertised position within a defensive 64-position metadata limit;
larger/negative counts and missing argument arrays are explicitly unavailable,
never silently truncated. This limit does not define a capture buffer or wire ABI.

- `Complete`: nonempty, paired entry/return names with resolved positional types,
  usable counts, and recognized stability attributes.
- `Partial`: some advertised probe identities are available, but discovery,
  pairing, or individual metadata failed. Check per-probe/per-argument diagnostics
  as well as snapshot-wide diagnostics.
- `Unavailable`: no advertised probe data could be returned, including missing
  device, denied library access, or an empty/failed inventory.

Absent count differs from a known zero count. Absent type differs from a valid
type spelling. Probe/argument stability attributes and DTT_FL_USER flags are
copied without turning them into semantic decoding or safe-copy permissions.
Discovery does not compile/enable/start probes, execute commands, or load modules.
Callers must serialize library use; no thread-safety guarantee is made.

RAII closes successfully opened handles on ordinary returns and exceptions.
The C callback catches C++ exceptions and rethrows only after returning from the
library iterator. Allocation failures may propagate to the caller after cleanup;
library query failures instead produce explicit availability/diagnostic data.

This is an internal component, not a stable public API, catalog of callable
implementations, or persisted trace format. Semantic names/directions, syscall
numbers, ABI classification, argument value capture, safe decoding, filtering,
event delivery and application integration remain separate increments. No
Linux kernel/userspace structures are included or modified.

## Native reproduction

Copy the two component files, [test_syscall_metadata.cpp](test_syscall_metadata.cpp),
and the unchanged [C audit](audit_syscall_metadata.c) into a fresh mode-0700 VM
directory, preserving `src/tracer/freebsd/` and `tests/freebsd/` paths. Set
`testdir` to that exact directory. Use ordinary `/bin/sh`, the installed compiler,
already-loaded modules, and the authorized `doas` access:

```sh
mkdir -m 700 "$testdir/results" || exit 1
resultdir="$testdir/results"
c++ -std=c++17 -Wall -Wextra -Werror -O0 -g -c \
    "$testdir/src/tracer/freebsd/syscall_metadata.cpp" -o "$testdir/syscall_metadata.o" \
    >"$resultdir/component-build.stdout" 2>"$resultdir/component-build.stderr" || exit 1
c++ -std=c++17 -Wall -Wextra -Werror -O0 -g \
    "$testdir/tests/freebsd/test_syscall_metadata.cpp" "$testdir/syscall_metadata.o" \
    -o "$testdir/test_syscall_metadata" \
    -Wl,--wrap=dtrace_open,--wrap=dtrace_close,--wrap=dtrace_probe_info,--wrap=ctf_type_name \
    -ldtrace -lctf >"$resultdir/test-build.stdout" 2>"$resultdir/test-build.stderr" || exit 1
cc -std=c11 -Wall -Wextra -Werror -O0 -g \
    "$testdir/tests/freebsd/audit_syscall_metadata.c" -o "$testdir/audit_syscall_metadata" \
    -ldtrace -lctf >"$resultdir/audit-build.stdout" 2>"$resultdir/audit-build.stderr" || exit 1
doas "$testdir/audit_syscall_metadata" >"$resultdir/audit.tsv" 2>"$resultdir/audit.stderr"
printf '%s\n' "$?" >"$resultdir/audit.status"
for mode in normal info-failure type-failure large-count negative-count null-arguments callback-exception; do
    doas "$testdir/test_syscall_metadata" "$mode" \
        >"$resultdir/$mode.tsv" 2>"$resultdir/$mode.stderr"
    printf '%s\n' "$?" >"$resultdir/$mode.status"
done
"$testdir/test_syscall_metadata" denied >"$resultdir/denied.tsv" 2>"$resultdir/denied.stderr"
printf '%s\n' "$?" >"$resultdir/denied.status"
```

Every test executable status should be zero: the `denied` test asserts expected
unavailable access, and fault tests assert explicit partial data or exception
cleanup. These are successful tests of failure behavior. If the ordinary identity
can open DTrace on another host, report the denied profile as unverified; do not
weaken its assertion or change device permissions to force a result.

Linker wrappers exist only in the test executable. Normal calls forward to the
real library; fault modes alter one `sendfile:entry` metadata query or its seventh
type lookup. Tests also count actual component handle opens/closes. The exception
case synthetically throws `std::bad_alloc` inside the callback's type lookup;
it does not exhaust VM memory. Each profile performs discovery twice. Normal
snapshots are inspected after closure/reopening and independently copied.

Retrieve `results` and verify locally:

```sh
python3 tests/freebsd/verify_syscall_metadata.py /path/to/results
```

The verifier compares every normal probe/type/flag/attribute with the independent
fresh C audit and checks all eight profiles. Record input hashes and environment
versions. After retrieving evidence, check for remaining test processes and remove
only the exact private VM directory. Preserve modules and unrelated state.
Reverting this increment removes the new component/tests and its documentation;
existing application behavior is unaffected because it does not reference them.
