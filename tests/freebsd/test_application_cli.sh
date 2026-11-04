#!/bin/sh
# SPDX-License-Identifier: MIT
# Run as an ordinary user. All error cases fail before starting live capture.
set -eu
umask 077
test "$#" -eq 2 && test "$(id -u)" -ne 0
app=$1 out=$2
mkdir "$out"
count=0
expect()
{
    expected=$1; shift; count=$((count + 1))
    if "$app" "$@" > "$out/$count.stdout" 2> "$out/$count.stderr"; then status=0; else status=$?; fi
    test "$status" -eq "$expected" || { echo "FAIL CLI case $count: got $status expected $expected"; exit 1; }
}
expect 0 --help
expect 0 --version
expect 2 -p 0
expect 2 -p -1
expect 2 -p 1,2,3,4,5,6,7,8,9,10,11
expect 2 -e ''
expect 2 --max-events 0
expect 2 --max-events 1000001
expect 2 --max-bytes 268435457
expect 2 --duration-ms 0
expect 2 --dump
expect 2 -f x --collect
expect 2 -f x --duration-ms 1
expect 2 -f x --no-stacks
expect 2 -p 1 -p 2
expect 2 --unknown
expect 1 --list-events
expect 1 --collect "$out/live.db" --duration-ms 1
test ! -e "$out/live.db"
printf 'keep this content\n' > "$out/exists.db"
expect 2 -c "$out/exists.db"
test "$(cat "$out/exists.db")" = 'keep this content'
expect 2 -c "$out/missing/file.db"
printf 'not a database\n' > "$out/bad.db"
expect 1 -f "$out/bad.db" --dump
ln -s "$out/bad.db" "$out/link.db"
expect 1 -f "$out/link.db" --dump
printf 'PASS: %s application CLI/rejection cases\n' "$count"
