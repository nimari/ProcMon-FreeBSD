# Native FreeBSD application

Target: FreeBSD 15.1 amd64, native ELF64. This is a community port of
Microsoft ProcMon-Linux. Native implementation version: 2.2.2.1. This is not an
official Microsoft FreeBSD release.
The Linux eBPF backend remains selected on Linux. FreeBSD uses base libdtrace,
CTF metadata, libprocstat/libelf and curses/panel. SQLite is bundled by default;
an installed SQLite library can be selected explicitly.

## Build and run

On FreeBSD, install `cmake-core` if CMake is absent. A base C/C++ compiler and
DTrace syscall provider are required. Load `dtraceall` as an administrator if
needed; the application does not load modules or change system policy.

```sh
cmake -S . -B build/freebsd -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build/freebsd -j2
ctest --test-dir build/freebsd --output-on-failure
./build/freebsd/procmon --version
./build/freebsd/procmon --help
```

To use installed SQLite headers and a library (version 3.33.0 or later), configure
a separate build with `-DPROCMON_USE_SYSTEM_SQLITE=ON`. CMake then uses
`SQLite::SQLite3` and does not build the bundled SQLite target. The resulting
executable requires that installed library at runtime. The default remains OFF.

`PROCMON_INSTALL_DOCS` defaults to ON. Set it to OFF to omit the supplemental
README; the executable, manual, license and SQLite notice remain installed.
Use `CMAKE_INSTALL_PREFIX`, the GNU install directory settings and `DESTDIR` for
prefix selection and staging. The FreeBSD targets retain frame pointers, while
debug information follows the build type and caller-supplied compiler flags.
Use the bundled default build with the standalone package script; a system-library
package needs declared runtime dependencies through the ports framework.

Choose an already running native process and replace `1234` with its PID:

```sh
doas ./build/freebsd/procmon -p 1234
doas ./build/freebsd/procmon -p 1234 -e openat,read,write -c capture.db
# Stop headless capture with Ctrl-C, or add --duration-ms 10000.
doas ./build/freebsd/procmon -f capture.db
# Export typed JSON Lines, with no terminal UI:
doas ./build/freebsd/procmon -f capture.db --dump > capture.jsonl
```

Live capture needs tracing privileges. Replay needs only read access to the
trace. Capture files are mode 0600, so a root-created trace normally needs doas
to replay. Export refuses to overwrite an existing path. Interactive mode needs
at least 80 columns by 24 rows. F1 help, F2 sort, F3 search, F4 filter, F5
pause/resume, F6 export, F8 statistics, Enter event details, q/F9 quit. Arrow/page
keys scroll event details. Repeated F6 exports use numbered new files and leave
previous snapshots intact. The export notice stays visible until the next key.
Quitting the UI stops tracing; use F6 to save first.

Omitting `-e` selects every available native syscall schema. Omitting `-p` selects
native user processes except the monitor. Selected PIDs bind to the inspected
process identity; capture stops when all selected targets exit. Exec changes the
selected identity and ends capture with an explicit failure. Child processes are
not automatically added to a selected PID list. At most ten PIDs may be selected.

## Data and quality

Arguments retain all metadata positions, up to eight 64-bit lanes. On the tested
kernel there are 594 native probe pairs, including a seven-argument syscall.
Names/types come from native CTF metadata; arguments without curated names use
`arg0`, `arg1`, etc. Raw pointer arguments remain available even when there is no
snapshot. Selected pathname snapshots are bounded to 256 bytes; selected input
and output buffers to 32 bytes; user stacks to 16 PCs. A limit flag means the
snapshot reached its bound, including values exactly as long as that bound.
`--no-strings`, `--no-buffers` and `--no-stacks` disable those optional features.
Complex structures, iovecs, argv/envp and arbitrary pointed-to objects are not
recursively decoded. ELF symbols are best effort; unavailable mappings/symbols
are marked and persisted for replay. There is no kernel-stack or source-line view.

Time is relative to a DTrace BEGIN timestamp, in nanoseconds in storage/JSON and
milliseconds in the duration column. The UTC display epoch is a userspace start
label, not an exact conversion from the DTrace clock. Per-thread entry/return
correlation preserves errno separately from result. Restart, control transfer,
entry-only exit, cancelled and incomplete states stay explicit. An unfinished
cancelled read has no fabricated output buffer or return. Captures retain quality
metadata for runtime faults, drops, unresolved events, missing snapshots, pause
gaps, target changes and stop reason. Faults/drops/incomplete data cause exit 1;
signal stops return 130/143. A partial capture is useful evidence, not a promise
that every syscall completed or every byte was observed.

FreeBSD SQLite traces carry a separate application ID, version, platform and
typed event codec. Linux files are rejected rather than reinterpreted. JSON
strings use byte-to-codepoint encoding: recover binary bytes by encoding the
parsed string as Latin-1. JSON integers retain exact lanes; consumers must avoid
converting 64-bit integers to IEEE double.

Live storage defaults to 100,000 events and 64 MiB of encoded/display payload.
`--max-events` accepts up to 1,000,000 and `--max-bytes` up to 256 MiB. These are
payload budgets, not total process RSS limits; SQLite indexes, correlation, symbol
caches and DTrace buffers have additional bounded allocations. Reaching a budget
ends capture as an explicit failure and exports the retained data in headless
mode. A failed transaction is rolled back as a whole. Replay validates all typed
rows and their query columns before loading, with a 256 MiB payload budget. JSON
dump and search stream rows rather than copying the entire trace into vectors.

## Scope of validation

Runtime tests select only owned fixture PIDs, exercising the full native catalog,
file calls, loopback sockets, seven argument positions, concurrent threads,
process calls, binary buffers, stack symbols, filtering, signals, target exit and
exec/ABI rejection. Tests exercise the real terminal UI in a PTY and verify
terminal restoration. The default unfiltered mode has not been exercised against
unrelated user workloads. Performance and loss under sustained production load,
other FreeBSD releases/architectures/ABIs, jails and Linux runtime regression are
outside the validated scope. Native syscall probes and kernel CTF fields are
private interfaces; a different kernel needs validation. No kernel/sysctl/boot
policy changes are made by the application.

See the [native architecture](ARCHITECTURE.md), [test instructions](../../tests/freebsd/README.md),
and [validation summary](VALIDATION.md) for implementation and test details.
The [ports preparation guide](../../dist/freebsd/PORTS.md) records remaining
packaging work.
