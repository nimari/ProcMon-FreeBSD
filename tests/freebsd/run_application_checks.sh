#!/bin/sh
# SPDX-License-Identifier: MIT
# Native privileged integration tests: only owned fixture children are selected.
set -eu
umask 077
if [ "$#" -ne 5 ] || [ "$(id -u)" -ne 0 ]; then
    echo 'usage (as root): run_application_checks.sh absolute-build fresh-evidence fixture-uid fixture-gid compat-fixture' >&2
    exit 2
fi
b=$1 out=$2 uid=$3 gid=$4 compat=$5
test "$uid" -gt 0
mkdir "$out"
# Fixture children need traversal, while evidence files remain private.
chmod 0711 "$out"
for p in all core read write openat self exit7 cancel term fault broken killed exec_native exec_compat compat zombie limit byte-limit no-extras; do
    "$b/test_freebsd_runtime" "$b/procmon" "$b/freebsd_app_fixture" "$compat" "$out" "$uid" "$gid" "$p" >> "$out/results.log" 2>&1
    if [ -f "$out/$p.db" ]; then "$b/procmon" -f "$out/$p.db" --dump > "$out/$p.jsonl"; fi
done
mkdir "$out/advanced" "$out/ui"
chmod 0711 "$out/advanced" "$out/ui"
"$b/test_freebsd_runtime" "$b/procmon" "$b/freebsd_advanced_fixture" "$compat" "$out/advanced" "$uid" "$gid" all >> "$out/results.log" 2>&1
"$b/procmon" -f "$out/advanced/all.db" --dump > "$out/advanced/all.jsonl"
for p in replay small resize interrupt; do
    "$b/test_freebsd_ui" "$b/procmon" "$out/all.db" "$out/ui" "$p" >> "$out/results.log" 2>&1
done
"$b/test_freebsd_ui" "$b/procmon" "$b/freebsd_app_fixture" "$out/ui" live "$uid" "$gid" unused >> "$out/results.log" 2>&1
for db in "$out/ui/"*.db; do "$b/procmon" -f "$db" --dump > "$db.jsonl"; done
cp "$out/ui/"*.db.2.db.jsonl "$out/ui/live.jsonl"
"$b/procmon" -f "$out/all.db" --dump -e read > "$out/replay-read.jsonl"
"$b/procmon" --help > "$out/help.txt"
"$b/procmon" --version > "$out/version.txt"
"$b/procmon" --list-events > "$out/catalog.txt"
ctest --test-dir "$b" --output-on-failure > "$out/ctest.txt"
echo 'PASS: native application runtime and PTY cases; independently verify JSON/fixture oracles with verify_application.py'
