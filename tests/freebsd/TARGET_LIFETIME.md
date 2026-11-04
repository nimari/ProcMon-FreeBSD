# Diagnostic target validation and lifetime

The standalone FreeBSD/amd64 diagnostic exercises target validation and lifetime
handling independently of the full application. Build and basic usage
remain in [DIAGNOSTIC.md](DIAGNOSTIC.md).

## Policy

Before opening DTrace, the driver reads the selected PID with `KERN_PROC_PID`.
It requires the expected `kinfo_proc` layout, a live user process and exactly
`FreeBSD ELF64` emulation. Missing/invisible, zombie, kernel and compatibility
targets fail before tracing. A real FreeBSD ELF32 executable was used to test
compatibility rejection; unsupported ABIs are not treated as empty captures.

The new [TargetWatch](../../src/tracer/freebsd/diagnostic/target_watch.h) arms a
private kqueue for NOTE_EXIT and NOTE_EXEC, then repeats the identity snapshot
and checks pending notifications. Failure to inspect/register/watch the target
is fatal, never a reason to fall back to numeric-PID-only capture. Snapshot
identity uses the kernel process address and boot-relative process start timeval.
`ki_start` includes boot time; the watcher subtracts a stable `kern.boottime`
snapshot to recover the kernel value. A boot-time adjustment during the read
fails preflight for retry. These values identify the process; they are not event
timestamps and are never used to adjust DTrace clocks.

The driver supplies that identity through an optional FreeBSD-only configuration
field. Every generated entry and return predicate checks PID, monitor exclusion,
kernel process address, kernel start seconds/microseconds and current ELF64 ABI.
An unrelated process reusing the PID/address with a different start value cannot
match these predicates, including before the userspace watcher reacts. Kernel
CTF is required; missing types/probes or read faults fail capture explicitly.
Actual kernel addresses are kept out of JSON and diagnostics. Existing callers
omitting the optional identity retain their previous generated source and policy.
The low-level controller does not discover/validate target identity by itself.

The driver checks the watch again after DTrace starts and before publishing ready.
An exit/exec at that point is a startup failure: it stops/drains/closes capture,
publishes only a failed summary, and suppresses provisional ready/event/notice
output. Decoder counts in that summary can include consumed observations which
were never published. It also checks pending notifications during polling and
once more after final drainage.

After ready, target exit requests an ordinary completed stop. A clean final
decoder/session can succeed even if the target exited nonzero or was signalled;
capture completeness is distinct from target success. Observed unresolved calls
still fail final quality. Any later exec ends this pilot capture as Failure,
including native-to-native exec. Exec wins if NOTE_EXEC/NOTE_EXIT coalesce.
No reattachment, child following, target signalling or reaping is performed.
A watch error stops/drains and marks Failure. SIGINT/SIGTERM still request explicit
cancellation and leave the target alone; underlying/policy failures take priority.
The first existing controller diagnostic is retained when one exists, with the
target stop cause identifying a concurrent exec/watch failure separately.

Ready and summary records add a `target` object with `validated`, `abi`,
`start_seconds`, `start_microseconds`, `exit_status` and `stop_cause`. Start values
are boot-relative identity values. `exit_status` is raw wait(2) encoding from
NOTE_EXIT, not the diagnostic executable's exit code; decode it with the native
wait macros. It is null when exit was not observed. Causes include preflight,
capture_start, duration, signal, exit, exec, watch_error and capture_failure.
The first duration/signal/exit cause is retained; exec supersedes it. Values are
explicitly unknown before validation. Output remains the additive pilot JSON
Lines v1, not the application's trace format or a stable public persistence ABI.

## Reproduce

On FreeBSD amd64, from the repository root as an ordinary user with existing
`doas`, compiler/DTrace headers/library, provider and base make:

```sh
run_dir=$(mktemp -d /tmp/procmon-target-parent.XXXXXX)
sh tests/freebsd/run_target_checks.sh "$run_dir/run"
```

The [runner](run_target_checks.sh) requires a new absolute output directory,
builds twelve targets with warnings as errors, checks six unit suites, exercises
seventeen driver profiles and four identity-guard profiles, runs the existing
thirteen CLI cases and rejects missing/kernel targets. It uses installed base
32-bit libraries to build an actual compatibility fixture; it installs nothing.
If those libraries are absent, record that limitation and stop rather than
silently skipping ABI validation or installing dependencies. Build results and
source identities are logged; failures stop the script. Use a fresh directory
for each run. Paths must have no whitespace for the small make/source-list recipe.

The fixtures already exec before attachment and publish readiness while blocked
on a supervisor-owned gate. Only the test supervisor creates, signals, releases
and reaps its children. A separate test-linked driver injects a target exit inside
`dtrace_go` and an error from the watched kqueue after ready; production has no
test-hook/environment path. Unit wrappers inject layout, registration, identity,
clock and error responses and check watcher descriptor counts after scope exit.
These controlled injections are distinguished from actual kernel notifications.

Results are exported as a user-owned `run/evidence.tar.gz` using privileged tar
to read private root-owned test logs. Transfer/extract on a machine with Python 3,
keeping the fixture subdirectories, and run:

```sh
python3 tests/freebsd/verify_target.py /absolute/path/to/results /absolute/path/to/repository
```

The verifier also uses unchanged [diagnostic checks](verify_diagnostic.py). It checks
24 source/recipe/runner identities, independent syscall oracles, ABI/lifetime
metadata, clock/return/path/state fields, notice counts, resource/drain status,
target survival and eight prior plus five new corruption controls. Compilers,
tests and verifier must all pass; a supervisor exit alone is insufficient proof.
The runner's final process check expects pgrep status 1 (none), never zero.
After preserving evidence, remove only the exact private run/parent directory
created for that test, using existing privilege where required.

## Limits

No forced live PID reuse was attempted and no PID-allocation kernel settings
were changed. Native tests prove that mismatched address, start-second and
start-microsecond guards exclude real fixture activity; this is controlled
identity mismatch, not a claim that a real recycled PID was observed. The token
uses FreeBSD kernel process internals and microsecond start-time precision,
not a public opaque generation identifier. Revalidate it on target updates;
it is not a formal uniqueness guarantee across all possible kernel lifecycles.

Preflight reads/registration are sequential, not an atomic kernel attach.
Rechecking notifications/identity and enforcing probe predicates closes the
tested races conservatively; startup changes fail rather than claim a complete
capture. Same-ABI post-exec observations can arrive before userspace stops;
they remain provisional and final capture is Failure. Current non-native ABI
calls are suppressed by the predicate and syscall provider selection. This does
not establish follow-exec semantics, arbitrary restart/nested-call correctness,
performance under sustained load, or complete ProcMon feature coverage.

Read-only source references: FreeBSD's [kinfo_proc layout](https://github.com/freebsd/freebsd-src/blob/releng/15.1/sys/sys/user.h),
[snapshot population/start-time conversion](https://github.com/freebsd/freebsd-src/blob/releng/15.1/sys/kern/kern_proc.c),
and [kqueue implementation](https://github.com/freebsd/freebsd-src/blob/releng/15.1/sys/kern/kern_event.c).
The VM's installed headers/source and kqueue(2) manual were also inspected.
See the [validation summary](../../docs/freebsd/VALIDATION.md).
