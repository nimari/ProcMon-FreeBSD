# Native metadata and bounded user-stack experiment

Target: FreeBSD 15.1 / amd64. This increment adds a discovery-only library
inventory and one raw stack profile to the isolated consumer. These checks exercise the library and isolated consumer independently of the application.

## Inventory

[audit_syscall_metadata.c](audit_syscall_metadata.c) opens the installed library,
iterates `syscall:freebsd:*:entry` and `return`, and calls `dtrace_probe_info`.
It records argument counts, positional CTF type names, user-type flags, and
probe/argument stability attributes. It closes the handle without compiling,
enabling, or starting probes. It requires the already-loaded DTrace device;
it does not load modules. Link with both `-ldtrace` and `-lctf`.

`PROBE` rows contain kind, function, count, three name attributes and three
argument attributes. `ARG` rows contain kind, function, zero-based position,
user-type flag, and type name. The final `AUDIT_END` contains totals, maximum
counts, failure counts, and closure status. API/type-resolution failures produce
diagnostics and nonzero status; retain those outputs to identify coverage gaps.

This inventories advertised metadata, not callable implementations. Obsolete,
compatibility, reserved, and optional-module entries can appear. Zero-argument
metadata does not prove that an obsolete entry is a supported zero-argument
syscall. Positional types do not supply semantic names, pointer direction,
buffer-length relationships, valid flags, or argument display rules. The
user-type flag alone must not authorize pointer dereferencing. Catalog/number
mapping and semantic decoding need separate, release/ABI-specific validation.

## Stack profile

[stack_capability.d](stack_capability.d) uses the original fixture's start/stop
markers and captures `ustack(8)` only for that PID's marked `openat` entries.
The consumer accepts `normal --stacks` only. Its existing macro argument `$2`
must be zero; the BEGIN predicate references it explicitly.

The record decoder validates action kinds, enclosing bounds, widths, eight-frame
descriptor depth, and zero string-table size. It copies three scalar fields and
a 72-byte stack payload: one PID word followed by eight PC words. The payload PID
must match the scalar PID and gated child. It never retains library-owned data
pointers or invokes libdtrace's stack formatter/symbol resolver.

Each `STACK` row contains PID, TID, raw DTrace timestamp, bound 8, nonzero count,
and eight hexadecimal PC slots. `STACK_COUNTS` reports samples and total nonzero
PCs. Empty stacks fail this fixture profile. Production code will need explicit
unavailable/truncated status rather than treating every empty stack as fatal.
No symbol identity, complete unwind, ASLR support, or optimized-binary coverage
is established. The unchanged fixture is compiled with frame pointers retained.

## Reproduce

Use a fresh private mode-0700 VM directory, ordinary `/bin/sh`, existing compiler,
already-loaded modules, and the authorized `doas` access. Copy the new audit and D
script plus all inputs from [SESSION_CONTRACT.md](SESSION_CONTRACT.md). Set
`testdir` to that exact directory. Check each build before running captures:

```sh
cc -std=c11 -Wall -Wextra -Werror -O0 -g \
    "$testdir/audit_syscall_metadata.c" -o "$testdir/audit_syscall_metadata" \
    -ldtrace -lctf || exit 1
cc -std=c11 -Wall -Wextra -Werror -O0 -g \
    "$testdir/libdtrace_consumer.c" -o "$testdir/libdtrace_consumer" -ldtrace || exit 1
cc -std=c11 -Wall -Wextra -Werror -O0 -g -fno-omit-frame-pointer -pthread \
    "$testdir/syscall_fixture.c" -o "$testdir/syscall_fixture" || exit 1
mkdir -m 700 "$testdir/results" "$testdir/results/audit" "$testdir/results/stacks" || exit 1
doas "$testdir/audit_syscall_metadata" >"$testdir/results/audit/metadata.tsv" \
    2>"$testdir/results/audit/stderr"
printf '%s\n' "$?" >"$testdir/results/audit/exit-status"
doas "$testdir/libdtrace_consumer" "$testdir/stack_capability.d" \
    "$testdir/syscall_fixture" "$testdir/results/stacks" "$(id -u)" "$(id -g)" \
    normal --stacks >"$testdir/results/stacks/records.tsv" \
    2>"$testdir/results/stacks/stderr"
printf '%s\n' "$?" >"$testdir/results/stacks/exit-status"
```

Rebuild the clock fixture and portable boundary check, and rerun all ten prior
profiles because the consumer changed. Follow the preceding instructions with
case directories inside `results`. Retrieve that directory and run locally:

```sh
python3 tests/freebsd/verify_metadata_stack.py /path/to/results UID GID
python3 tests/freebsd/verify_libdtrace.py /path/to/results UID GID
python3 tests/freebsd/verify_clock_signal.py /path/to/results UID GID
python3 tests/freebsd/verify_session_contract.py /path/to/results UID GID
```

The new verifier checks inventory completeness against advertised counts,
resolved types, matching probe names, totals/closure, exact stack bounds,
nonempty PCs with zero padding, fixture PID/TIDs, marker intervals, and complete
consumer lifecycle. Counts and positional coverage do not prove semantic catalog
completeness. Per-CPU delivery may reorder rows; compare timestamps and identities.

Record source hashes, verify no experiment process remains, and remove only the
exact private VM directory after retrieving evidence. Leave modules and policy
settings unchanged.
