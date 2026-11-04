# ProcMon community FreeBSD port

Version 2.2.2.1. Validated on FreeBSD 15.1-RELEASE-p6 amd64 with the native
FreeBSD ELF64 syscall ABI. This is a community port, not an official Microsoft
FreeBSD release. The source project is https://github.com/microsoft/ProcMon-Linux.

Run `procmon --help` and `man procmon` for the full interface. Live capture needs
tracing privileges and the DTrace syscall provider. As administrator, load
`dtraceall` if needed; the app never loads modules or changes system policy.

Replace 1234 with a live native process PID:

    doas procmon -p 1234
    doas procmon -p 1234 -e openat,read,write -c capture.db
    doas procmon -f capture.db
    doas procmon -f capture.db --dump > capture.jsonl

Ctrl-C stops/drains headless capture and saves it; it does not kill the target.
Files are private (0600) and new exports never overwrite existing files. Replay
needs file read access, not tracing privileges. Interactive mode requires 80x24
or larger. Use Enter for details, arrows/page keys to scroll, F1 help, F2 sort,
F3 search, F4 filter, F5 pause/resume, F6 export, F8 stats and q/F9 quit. Repeated
UI exports use numbered files. Save with F6 before quitting the UI.

All available native syscall schemas are enabled by default. All advertised raw
arguments are retained (up to eight). Selected paths are copied up to 256 bytes,
selected buffers up to 32 bytes, and user stacks up to 16 PCs. Pointer structures
are not recursively decoded. ELF symbol resolution is best effort. Unavailable
values, restart/control/exit/cancel states, faults, drops, pause gaps and incomplete
captures remain explicit. Selected processes stop on exit; exec ends the selected
identity-scoped capture as a failure. Children are not automatically selected.

Default live budgets: 100,000 events and 64 MiB payload; --max-events/--max-bytes
can raise these to 1,000,000 / 256 MiB. Payload is not total RSS. Budget exhaustion
ends capture with an explicit failure. FreeBSD trace files have a separate format;
Linux traces are rejected. JSON binary strings use byte-to-codepoint encoding:
encode parsed strings as Latin-1 to recover bytes. Keep JSON 64-bit integers exact.

The tests use owned fixture PIDs, including loopback network, threads, process
calls, seven argument positions, failures, signals, replay and real terminals.
Unfiltered unrelated production workloads, sustained load, other releases/ABIs,
jails and Linux runtime regression have not been validated. Native DTrace probes
and kernel CTF fields are private interfaces. Validate a different kernel before
relying on it. Exit codes: 0 success, 1 capture/storage failure, 2 usage, 130/143
signal stop. Inspect trace metadata to assess completeness.

MIT project license: see LICENSE. Bundled SQLite is public domain; its notice is
in SQLITE-NOTICE. No publication, ports acceptance or Microsoft endorsement is
implied by this community project.
