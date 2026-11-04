# FreeBSD validation

## Verified application baseline

The following results were obtained on FreeBSD **15.1-RELEASE-p6 GENERIC amd64**
with base Clang 19.1.7, CMake 3.31.12 and bundled SQLite 3.51.3. The native
implementation reports version 2.2.2.1. These are results for the working baseline
from which the public branch was curated; they are not new ports-build results.

| Check | Baseline outcome |
| --- | --- |
| Clean RelWithDebInfo native build | Pass |
| Seven CTests | 322 checks pass |
| Supervised application runtime | 20 cases pass |
| Terminal UI through a real PTY | Five profiles pass, including resize, interruption and live export |
| Ordinary-user CLI and rejection checks | 22 pass |
| Independent application/fixture verification | 296 checks pass; nine corruption controls rejected |
| Local package install, integrity, installed capture/replay, manual and deinstall | Pass |
| Standalone diagnostic suite | 215 unit checks, 17 runtime profiles, four identity guards and 13 CLI cases pass |
| Independent diagnostic verification | Pass; eight original and five target corruption controls rejected |
| Static Linux preservation | Six shared source/header views and default CMake body unchanged |

The tests select only owned fixtures. The inspected native catalog contains 594
entry/return probe pairs. Fixtures exercise concurrent threads, success/error
file calls, binary buffers, loopback sockets, process calls, all seven argument
positions of `sendfile`, selected stack symbols, filtering and controlled faults.
Live UI checks produce separate private snapshots, retain the pause gap and mark
an active snapshot incomplete. Tests verify terminal restoration and target
survival after tracing stops or fails.

## Public source preparation

Initial public source curation retained the working native implementation, build
inputs and test assertions. Two test comments/docstrings use descriptive terminology, and
the static preservation checker references the original public upstream commit
instead of a private development checkpoint. Technical instructions replace
private development records. See [the test guide](../../tests/freebsd/README.md)
for commands to reproduce the current suites.

During curation, local Python/shell syntax and relative documentation links pass.
Portable generator tests pass 19 checks, identity-generation tests pass eight,
and the portable event-contract test passes. The static Linux source comparison
also passes. These local checks do not replace a fresh FreeBSD build.
The system-library ports build, stage QA, clean-jail testing and final installed
runtime tests remain required before the 2.2.2.2 release is declared ready. The
[ports guide](../../dist/freebsd/PORTS.md) records that status.

## Native dependency build validation

The FreeBSD dependency build changes were checked on the same 15.1-RELEASE-p6
amd64 target. Both bundled SQLite and installed SQLite 3.53.4 pass seven CTests
(322 checks each) and 22 ordinary-user CLI cases each. Documentation ON/OFF,
legal notices, manual and custom-prefix staging pass. Production debug flags
follow the build type and caller; base startup objects may still carry debug data.

The logger/curses implementation at commit `393aa4b` passes this three-build
matrix, with seven CTests (322 checks) and 22 CLI cases per build:

| Logger / SQLite | Curses provider | Outcome |
| --- | --- | --- |
| Bundled | FreeBSD base | Pass |
| Installed source / installed SQLite | FreeBSD base | Pass |
| Installed source / installed SQLite | Ports ncurses 6.6 | Pass |

The installed logger is Easylogging++ 9.97.1. Compiler inputs and runtime library
paths confirm the selected providers; the logger source is compiled privately
with consistent thread-safe definitions, without linking its shared library.
The selected logger's MIT license matches the installed notice in staged files.
Missing logger source/license or curses inputs fail configuration. Switching
curses prefixes re-resolves the inputs and rejects an invalid replacement prefix.

All three builds reproduce the existing owned-fixture trace's JSON exactly and
pass a real PTY replay/control test with private debug logging and terminal
restoration. Five staged installs cover both dependency modes, documentation
ON/OFF and a custom prefix. The bundled standalone package contains the expected
six files; its helper rejects external dependencies and documentation OFF before
creating output. Linux preservation passes for seven shared source/header views
and the default CMake body.

These checks do not include new live capture with the dependency changes or a
ports-framework/poudriere build. Those remain release acceptance requirements.
No ProcMon package was installed during this dependency-build verification.

## Limits

Other releases, architectures, compatibility ABIs and jails are not supported by
this validation. Unfiltered capture of unrelated workloads, sustained-load loss
or performance guarantees, and Linux runtime regression have not been tested.
Native probes and kernel CTF fields are private interfaces; a different kernel
requires validation. Structures are not recursively decoded and symbol resolution
is best effort. This project does not claim Windows Process Monitor feature parity.
