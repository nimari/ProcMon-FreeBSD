#!/bin/sh
# SPDX-License-Identifier: MIT
# FreeBSD/amd64, ordinary user with existing doas; never installs dependencies.
set -eu
test "$#" -eq 1 || { printf 'usage: sh tests/freebsd/run_target_checks.sh NEW_ABSOLUTE_DIRECTORY\n' >&2; exit 2; }
case $1 in /*) ;; *) exit 2;; esac
run_dir=$1
test ! -e "$run_dir"
umask 077
mkdir "$run_dir" "$run_dir/build" "$run_dir/results"
build_dir=$run_dir/build
result_dir=$run_dir/results
capture_sources='src/tracer/freebsd/native_capture.cpp src/tracer/freebsd/native_program.cpp src/tracer/freebsd/native_event_decoder.cpp src/tracer/freebsd/dtrace_session.cpp'
cxx_flags='-std=c++17 -Wall -Wextra -Werror -O0 -g -pthread'
build()
{
    name=$1; shift
    if "$@" > "$result_dir/$name-build.stdout" 2> "$result_dir/$name-build.stderr"; then
        printf '0\n' > "$result_dir/$name-build.exit"
    else
        status=$?; printf '%s\n' "$status" > "$result_dir/$name-build.exit"; exit "$status"
    fi
}
build pilot make -s -f src/tracer/freebsd/diagnostic/Makefile BUILD_DIR="$build_dir"
build runtime c++ $cxx_flags tests/freebsd/test_target_runtime.cpp -o "$build_dir/runtime"
build fixture cc -std=c11 -Wall -Wextra -Werror -O0 -g -pthread tests/freebsd/target_fixture.c -o "$build_dir/fixture"
build fixture32 cc -m32 -std=c11 -Wall -Wextra -Werror -O0 -g -pthread tests/freebsd/target_fixture.c -o "$build_dir/fixture32"
build watch c++ $cxx_flags tests/freebsd/test_target_watch.cpp -Wl,--wrap=sysctl,--wrap=sysctlbyname,--wrap=kevent -o "$build_dir/watch"
build guard c++ $cxx_flags tests/freebsd/test_target_guard.cpp $capture_sources -ldtrace -o "$build_dir/guard"
build hooked c++ $cxx_flags src/tracer/freebsd/diagnostic/main.cpp tests/freebsd/target_driver_hooks.cpp $capture_sources -Wl,--wrap=dtrace_go,--wrap=kevent -ldtrace -o "$build_dir/hooked-pilot"
build generation c++ $cxx_flags tests/freebsd/test_target_program.cpp src/tracer/freebsd/native_program.cpp -o "$build_dir/generation"
build program c++ $cxx_flags tests/freebsd/test_native_program.cpp src/tracer/freebsd/native_program.cpp -o "$build_dir/program"
build decoder c++ $cxx_flags tests/freebsd/test_native_event_decoder.cpp src/tracer/freebsd/native_event_decoder.cpp -o "$build_dir/decoder"
build controller c++ $cxx_flags tests/freebsd/test_native_capture.cpp $capture_sources -ldtrace -o "$build_dir/controller"
build support c++ $cxx_flags tests/freebsd/test_diagnostic_support.cpp -o "$build_dir/support"
for unit in watch generation program decoder controller support; do
    "$build_dir/$unit" > "$result_dir/$unit.stdout" 2> "$result_dir/$unit.stderr"
    printf '0\n' > "$result_dir/$unit.exit"
done
for profile in all read write openat self exit7 cancel term fault broken killed exec_native exec_compat compat zombie startup watch_error; do
    pilot=$build_dir/procmon-freebsd-capture
    case $profile in startup|watch_error) pilot=$build_dir/hooked-pilot;; esac
    doas "$build_dir/runtime" "$pilot" "$build_dir/fixture" "$build_dir/fixture32" "$result_dir" "$(id -u)" "$(id -g)" "$profile" > "$result_dir/$profile.supervisor" 2> "$result_dir/$profile.supervisor-error"
    printf '0\n' > "$result_dir/$profile.exit"
done
for profile in matching address seconds microseconds; do
    mkdir "$result_dir/guard-$profile-files"
    doas "$build_dir/guard" "$build_dir/fixture" "$result_dir/guard-$profile-files" "$(id -u)" "$(id -g)" "$profile" > "$result_dir/guard-$profile.jsonl" 2> "$result_dir/guard-$profile.stderr"
    printf '0\n' > "$result_dir/guard-$profile.exit"
done
sh tests/freebsd/test_diagnostic_cli.sh "$build_dir/procmon-freebsd-capture" "$result_dir" > "$result_dir/cli.stdout" 2> "$result_dir/cli.stderr"
for target in 2147483647 2; do
    if doas "$build_dir/procmon-freebsd-capture" --pid "$target" --duration-ms 10 > "$result_dir/reject-$target.jsonl" 2> "$result_dir/reject-$target.stderr"; then exit 1;
    else printf '%s\n' "$?" > "$result_dir/reject-$target.exit"; fi
done
sha256 $capture_sources src/tracer/freebsd/native_capture.h src/tracer/freebsd/native_program.h src/tracer/freebsd/native_event_decoder.h src/tracer/freebsd/dtrace_session.h src/tracer/freebsd/diagnostic/main.cpp src/tracer/freebsd/diagnostic/support.h src/tracer/freebsd/diagnostic/target_watch.h src/tracer/freebsd/diagnostic/Makefile tests/freebsd/test_native_program.cpp tests/freebsd/test_native_capture.cpp tests/freebsd/test_native_event_decoder.cpp tests/freebsd/test_diagnostic_support.cpp tests/freebsd/test_diagnostic_cli.sh tests/freebsd/target_fixture.c tests/freebsd/target_driver_hooks.cpp tests/freebsd/test_target_*.cpp tests/freebsd/run_target_checks.sh > "$result_dir/inputs.sha256"
freebsd-version -ku > "$result_dir/environment.txt"
uname -m >> "$result_dir/environment.txt"
c++ --version >> "$result_dir/environment.txt"
make -V MAKE_VERSION >> "$result_dir/environment.txt"
file "$build_dir/fixture" "$build_dir/fixture32" > "$result_dir/fixture-abis.txt"
make -q -f src/tracer/freebsd/diagnostic/Makefile BUILD_DIR="$build_dir" "$build_dir/procmon-freebsd-capture"
printf '0\n' > "$result_dir/make-up-to-date.exit"
if pgrep -af '(^|/)(procmon-freebsd-capture|hooked-pilot|fixture|fixture32|runtime|guard)( |$)' > "$result_dir/processes.txt"; then exit 1;
else printf '%s\n' "$?" > "$result_dir/process-check.exit"; fi
doas tar -czf - -C "$run_dir" results > "$run_dir/evidence.tar.gz"
printf 'PASS: target checks; evidence %s/evidence.tar.gz\n' "$run_dir"
