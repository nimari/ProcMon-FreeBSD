#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare the native C++ component with the unchanged independent C audit."""

from pathlib import Path
import sys


def require(condition, message):
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def load(path):
    return [line.split("\t") for line in path.read_text().splitlines() if line]


def one(rows, tag):
    matches = [row for row in rows if row[0] == tag]
    require(len(matches) == 1, f"expected one {tag}")
    return matches[0]


def pairs(fields):
    items = [field.split("=", 1) for field in fields]
    require(all(len(item) == 2 for item in items), "malformed counters")
    values = dict(items)
    require(len(values) == len(items), "duplicate counters")
    return values


def inventory(rows):
    probes, args = {}, {}
    for row in rows:
        if row[0] == "PROBE":
            require(len(row) == 10 and row[1] in {"entry", "return"} and row[2] and
                    0 <= int(row[3]) <= 64 and all(row[4:]), "invalid probe metadata")
            key = tuple(row[1:3])
            require(key not in probes, "duplicate probe")
            probes[key] = row
        elif row[0] == "ARG":
            require(len(row) == 6 and row[1] in {"entry", "return"} and
                    row[4] in {"0", "1"} and row[5] and row[5] != "<unresolved>",
                    "invalid argument metadata")
            key = (row[1], row[2], int(row[3]))
            require(key not in args, "duplicate argument")
            args[key] = row
    expected = {(kind, name, index) for (kind, name), row in probes.items()
                for index in range(int(row[3]))}
    require(args.keys() == expected, "missing/extra argument index")
    entries = {name for kind, name in probes if kind == "entry"}
    returns = {name for kind, name in probes if kind == "return"}
    require(entries and entries == returns, "empty/unpaired native probe names")
    return probes, args, entries


if len(sys.argv) != 2:
    raise SystemExit("usage: verify_syscall_metadata.py results-directory")
root = Path(sys.argv[1])
for build in ("component", "test", "audit"):
    require(not (root / f"{build}-build.stdout").read_text() and
            not (root / f"{build}-build.stderr").read_text(), f"{build}: build diagnostics")
require(int((root / "audit.status").read_text()) == 0 and
        not (root / "audit.stderr").read_text(), "audit failed")
audit = load(root / "audit.tsv")
require(all(row[0] in {"PROBE", "ARG", "AUDIT_END"} for row in audit), "audit errors/unknown rows")
probes, arguments, entries = inventory(audit)
summary = {key: int(value) for key, value in pairs(one(audit, "AUDIT_END")[1:]).items()}
require(summary == {"entries": len(entries), "returns": len(entries), "arguments": len(arguments),
                    "max_entry": max(int(row[3]) for key, row in probes.items() if key[0] == "entry"),
                    "max_return": max(int(row[3]) for key, row in probes.items() if key[0] == "return"),
                    "info_failures": 0, "type_failures": 0, "closed": 1}, "audit totals/cleanup")
for mode in ("normal", "denied", "info-failure", "type-failure", "large-count",
             "negative-count", "null-arguments", "callback-exception"):
    require(int((root / f"{mode}.status").read_text()) == 0 and
            not (root / f"{mode}.stderr").read_text(), f"{mode}: test failure")
    rows = load(root / f"{mode}.tsv")
    status = pairs(one(rows, "METADATA_TEST")[1:])
    expected = {"mode": mode, "probes": "0" if mode in {"denied", "callback-exception"} else str(len(probes)),
                "opens": "0" if mode == "denied" else "2",
                "closes": "0" if mode == "denied" else "2",
                "injected": "0" if mode in {"normal", "denied"} else "2", "passed": "1"}
    require(status == expected, f"{mode}: counters/cleanup")
    if mode == "normal":
        require(all(row[0] in {"PROBE", "ARG", "METADATA_TEST"} for row in rows), "normal row types")
        require(inventory(rows) == (probes, arguments, entries), "C++ metadata differs from C audit")
        require(int(probes[("entry", "sendfile")][3]) == 7 and
                arguments[("entry", "sendfile", 6)][5] == "int", "seventh argument missing")
    elif mode == "denied":
        require(len(rows) == 2 and len(one(rows, "UNAVAILABLE")) == 2 and
                one(rows, "UNAVAILABLE")[1].startswith("dtrace_open failed:"),
                "ordinary-user denial not reported")
    else:
        require(len(rows) == 1, f"{mode}: unexpected test output")
    print(f"PASS: {mode}; repeated calls, expected availability and handle accounting")
print(f"PASS: exact positional types/flags/attributes for {len(entries)} native probe pairs "
      f"and {len(arguments)} argument positions; seventh argument preserved")
