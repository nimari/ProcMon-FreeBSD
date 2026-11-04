# Native FreeBSD architecture

The root CMake file selects `cmake/FreeBSD.cmake` on FreeBSD before Linux BCC,
eBPF, dependency fetches or Linux packaging are configured. Linux retains its
original build body. Shared UI and telemetry adapters use `__FreeBSD__` guards.

## Capture and event flow

1. `syscall_metadata` discovers native entry/return probes and their positional
   CTF argument types. The application retains every advertised position up to
   eight raw lanes; missing metadata is explicit.
2. The application capture layer validates selected native ELF64 process
   identities, generates trusted D source for the selected PIDs/syscalls and
   executes it through `DTraceSession`. The session owns the DTrace handle,
   callbacks, batches, notices and stop/drain lifecycle.
3. Entry/return records correlate by process, thread, syscall and start time.
   Selected paths, buffers and user stacks are bounded. The application retains
   return values, errno, incomplete/control states and quality metadata separately.
4. The engine converts native events into the telemetry consumed by the reused
   terminal display or headless collector. Symbol lookup uses process mappings
   and ELF data; unavailable symbols remain visible.
5. SQLite storage encodes typed native events and metadata for exclusive export,
   validated replay, query/display fields and streaming JSON Lines output.

The standalone diagnostic uses a separate three-operation program generator,
decoder and controller to test `openat`, `read` and `write` and their lifecycle.
It shares the session transport with the full application. The application has
its own catalog-based capture layer and is not limited to those three operations.

## Ownership and boundaries

The monitor owns its tracing resources and capture data. Observed processes are
not its children in normal use; stopping tracing does not kill them. Selecting a
PID binds capture to the inspected identity. Exit stops that selection, while
exec or an incompatible identity ends the capture with explicit failure. Children
are not automatically selected.

Live capture requires tracing privileges and an available syscall provider.
The application does not load modules or change boot, sysctl or privilege policy.
Unit tests run without those tracing privileges; supervised integration tests
create and manage their own fixture processes.

## Data contract and limits

The native SQLite application ID, schema and typed codec are separate from Linux
traces. The CLI rejects Linux captures rather than translating their contents.
JSON strings use byte-to-codepoint encoding: encode parsed strings as Latin-1 to
recover bytes. Consumers must preserve 64-bit integers exactly.

Paths are bounded to 256 bytes, selected buffers to 32 bytes and user stacks to
16 program counters. Complex pointed-to structures are not recursively decoded.
Payload budgets, incomplete snapshots, drops, runtime faults, pause gaps and stop
reasons remain explicit. A successful process exit alone does not prove complete
event capture; inspect trace quality metadata.

This implementation relies on private native probe/CTF interfaces and is validated
only on the target in [VALIDATION.md](VALIDATION.md). See
[APPLICATION.md](APPLICATION.md) for CLI semantics, budgets and exit statuses.
