# FreeBSD tests

Target: FreeBSD 15.1 amd64. The full application and standalone diagnostic have
separate supervised suites. Run from the repository root in an ordinary user
shell. Live checks need authorized `doas` access and the already available DTrace
syscall provider. The tests do not install dependencies or change system policy.

## Application unit and CLI checks

```sh
cmake -S . -B build/freebsd -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build/freebsd -j2
ctest --test-dir build/freebsd --output-on-failure
# Choose a new absolute directory; this script creates it exclusively.
sh tests/freebsd/test_application_cli.sh "$(pwd)/build/freebsd/procmon" /absolute/new-cli-results
```

Seven CTests exercise storage and native components without privileged tracing.
The CLI suite also runs without tracing privileges and checks rejection paths.
Do not run live DTrace integration tests in a build jail.

## Application runtime and terminal checks

The integration runner starts controlled fixtures, traces their PIDs, checks
signals/identity/quality and drives the real terminal UI through a PTY. It needs
base 32-bit compatibility libraries to build the rejection fixture. If absent,
record the unmet requirement; do not silently omit the ABI case.

```sh
cc -m32 -g -fno-omit-frame-pointer -pthread -DPROCMON_APP_FIXTURE_TIMEOUT=90 \
  tests/freebsd/target_fixture.c -o build/freebsd/freebsd_app_fixture32
build_dir="$(pwd)/build/freebsd"
# Choose a new absolute result directory under a parent accessible to the fixture UID.
doas sh tests/freebsd/run_application_checks.sh \
  "$build_dir" /absolute/new-app-results "$(id -u)" "$(id -g)" \
  "$build_dir/freebsd_app_fixture32"
```

Check every command's status and stop on failure. Evidence is private; preserve
it with an administrator-readable archive before moving it to a Python 3 machine.
On that machine, extract it as your ordinary user and run:

```sh
python3 tests/freebsd/verify_application.py /absolute/extracted-app-results --negative
```

Independent verification checks fixture oracles, raw argument lanes, clocks,
results/errno, symbols, buffers and quality. Nine deliberate evidence mutations
must be rejected. A supervisor's success alone is insufficient.

## Standalone diagnostic and component checks

[TARGET_LIFETIME.md](TARGET_LIFETIME.md) documents the current complete diagnostic
suite and verifier. It builds its own binaries and selects only supervised fixture
PIDs. [DIAGNOSTIC.md](DIAGNOSTIC.md) documents the diagnostic's CLI and limits.

The narrower experiments remain useful when investigating an individual layer:

| Layer | Instructions |
| --- | --- |
| Provider and independently observed syscalls | [SMOKE.md](SMOKE.md) |
| Raw API records | [LIBDTRACE.md](LIBDTRACE.md) |
| Clocks and cancellation | [CLOCK_SIGNAL.md](CLOCK_SIGNAL.md) |
| Experimental standalone event contract | [SESSION_CONTRACT.md](SESSION_CONTRACT.md) |
| CTF metadata and bounded stacks | [METADATA_STACK.md](METADATA_STACK.md) |
| Native metadata | [NATIVE_METADATA.md](NATIVE_METADATA.md) |
| Session lifecycle | [DTRACE_SESSION.md](DTRACE_SESSION.md) |
| Diagnostic event decoding | [NATIVE_EVENT_DECODER.md](NATIVE_EVENT_DECODER.md) |
| Diagnostic D generation | [NATIVE_PROGRAM.md](NATIVE_PROGRAM.md) |
| Diagnostic controller | [NATIVE_CAPTURE.md](NATIVE_CAPTURE.md) |

These layer tests use deliberately restricted schemas. Their limits do not
replace the full application's catalog or [documented behavior](../../docs/freebsd/APPLICATION.md).

## Linux preservation and package checks

```sh
python3 tests/freebsd/check_linux_preservation.py
```

This source comparison needs Git history containing original upstream commit
`a40cf056351d19830a96d2d22beed96a18f7707c`. Use a full clone rather than a source
archive or shallow history for this check. It compares shared files with FreeBSD
branches excluded and the unchanged Linux CMake body. It does not claim a Linux
runtime test.

`test_package.sh` verifies the original bundled-library local package. Ports
packages require the separate framework/jail/installed-host checks described in
[PORTS.md](../../dist/freebsd/PORTS.md). See
[VALIDATION.md](../../docs/freebsd/VALIDATION.md) for actual baseline results and
remaining release checks.
