#!/bin/sh
# SPDX-License-Identifier: MIT
# Run as an ordinary user. Own output directory and executable are arguments.
set -u
test "$#" -eq 2 || exit 2
pilot=$1
results=$2
check()
{
    name=$1
    expected=$2
    shift 2
    "$pilot" "$@" > "$results/cli-$name.stdout" 2> "$results/cli-$name.stderr"
    actual=$?
    printf '%s\n' "$actual" > "$results/cli-$name.exit"
    test "$actual" -eq "$expected" || exit 1
}
check help 0 --help
check missing 2
check zero 2 --pid 0
check negative 2 --pid -1
check overflow 2 --pid 2147483648
check garbage 2 --pid '1;id'
check unknown 2 --pid 1 --unknown value
check empty 2 --pid 1 --events ''
check trailing 2 --pid 1 --events read,
check duplicate 2 --pid 1 --pid 2
check value 2 --pid
check duration 2 --pid 1 --duration-ms 86400001
check denied 1 --pid "$$" --duration-ms 10
printf 'CLI_CASES\t13\n'
