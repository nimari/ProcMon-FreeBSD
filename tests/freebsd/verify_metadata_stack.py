#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate complete positional inventory and bounded fixture stack records."""

from collections import Counter
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
    parts = [field.split("=", 1) for field in fields]
    require(all(len(part) == 2 for part in parts), "malformed counters")
    result = dict(parts)
    require(len(result) == len(parts), "duplicate counters")
    return result


if len(sys.argv) != 4:
    raise SystemExit("usage: verify_metadata_stack.py results-directory uid gid")
root = Path(sys.argv[1])
uid, gid = sys.argv[2:4]
audit = root / "audit"
require(int((audit / "exit-status").read_text()) == 0 and
        not (audit / "stderr").read_text(), "inventory status/diagnostics")
rows = load(audit / "metadata.tsv")
require(all(row[0] in {"PROBE", "ARG", "AUDIT_END"} for row in rows),
        "inventory error/unknown row")
probes, arguments = {}, {}
for row in rows:
    if row[0] == "PROBE":
        require(len(row) == 10 and row[1] in {"entry", "return"} and row[2],
                "probe shape")
        key = tuple(row[1:3])
        require(key not in probes and 0 <= int(row[3]) <= 64 and all(row[4:]),
                "duplicate/invalid probe metadata")
        probes[key] = row
    elif row[0] == "ARG":
        require(len(row) == 6 and row[1] in {"entry", "return"} and
                row[4] in {"0", "1"} and row[5] and row[5] != "<unresolved>",
                "argument shape/type")
        key = (row[1], row[2], int(row[3]))
        require(key not in arguments, "duplicate argument")
        arguments[key] = row
expected = {(kind, name, index) for (kind, name), row in probes.items()
            for index in range(int(row[3]))}
require(arguments.keys() == expected, "missing/extra argument index")
names = {kind: {name for probe_kind, name in probes if probe_kind == kind}
         for kind in ("entry", "return")}
require(names["entry"] and names["entry"] == names["return"], "probe pairing")
summary = {key: int(value) for key, value in
           pairs(one(rows, "AUDIT_END")[1:]).items()}
require(summary == {"entries": len(names["entry"]), "returns": len(names["return"]),
                    "arguments": len(arguments),
                    "max_entry": max(int(row[3]) for key, row in probes.items()
                                     if key[0] == "entry"),
                    "max_return": max(int(row[3]) for key, row in probes.items()
                                      if key[0] == "return"),
                    "info_failures": 0, "type_failures": 0, "closed": 1},
        "inventory totals/cleanup")
distribution = Counter(int(row[3]) for key, row in probes.items() if key[0] == "entry")
wide = sorted(name for (kind, name), row in probes.items()
              if kind == "entry" and int(row[3]) > 6)
attributes = sorted({tuple(row[4:]) for row in probes.values()})
print(f"PASS: {summary['entries']} matched native probe pairs; "
      f"{len(arguments)} resolved positional types; entry counts {dict(sorted(distribution.items()))}")
print(f"Metadata: over-six calls={wide}; name/data/class and argument attributes={attributes}")

directory = root / "stacks"
require(int((directory / "exit-status").read_text()) == 0 and
        not (directory / "stderr").read_text(), "stack status/diagnostics")
status = pairs(one(load(directory / "api-status.tsv"), "API_STATUS")[1:])
require(status.pop("mode") == "normal", "stack mode")
status = {key: int(value) for key, value in status.items()}
pid = status.pop("pid")
require(pid > 0 and status == {
    "probes": 9, "records": 26, "zero_records": 2, "entries": 4, "returns": 0,
    "errors": 0, "drops": 0, "schema": 0, "started": 1, "stopped": 1,
    "drained": 1, "closed": 1, "reaped": 1, "child_status": 0, "startup_error": 0,
    "blocked": 0, "signal_sent": 0, "signal_seen": 0, "cancel_elapsed_ns": 0},
    "stack counters/lifecycle")
fixture = load(directory / "fixture.tsv")
require(one(fixture, "IDENTITY") == ["IDENTITY", str(pid), uid, gid] and
        one(fixture, "FIXTURE") == ["FIXTURE", str(pid), "16", "0"], "fixture identity/result")
expected_calls = [row for row in fixture if row[0] == "EXPECT"]
require(len(expected_calls) == 16 and all(len(row) == 10 and int(row[1]) == pid
                                        for row in expected_calls), "fixture call shape")
expected_threads = Counter(int(row[2]) for row in expected_calls if row[3] == "openat")
require(len(expected_threads) == 2 and set(expected_threads.values()) == {2},
        "fixture worker threads")
records = load(directory / "records.tsv")
require(all(row[0] in {"BEGIN", "START", "STOP", "STACK", "TARGET_EXIT", "END",
                      "STACK_COUNTS"} for row in records), "unknown stack row")
require(one(records, "BEGIN") == ["BEGIN", str(pid)] and one(records, "END") == ["END"] and
        one(records, "TARGET_EXIT") == ["TARGET_EXIT", str(pid), "0"], "stack boundaries/exit")
start, stop = one(records, "START"), one(records, "STOP")
require(len(start) == len(stop) == 3 and start[1] == stop[1] == str(pid), "marker shape")
begin, end = int(start[2]), int(stop[2])
require(0 < begin < end, "marker interval")
stacks = [row for row in records if row[0] == "STACK"]
require(len(stacks) == 4, "missing/extra stack sample")
threads, identities, depths = Counter(), set(), []
for row in stacks:
    require(len(row) == 14 and int(row[1]) == pid and row[4] == "8", "stack shape/PID/bound")
    tid, timestamp, count = int(row[2]), int(row[3]), int(row[5])
    require(tid > 0 and begin <= timestamp <= end and (tid, timestamp) not in identities,
            "stack TID/time/duplicate")
    identities.add((tid, timestamp))
    pcs = [int(value, 16) for value in row[6:]]
    require(1 <= count <= 8 and sum(pc != 0 for pc in pcs) == count and
            all(0 < pc < 2**64 for pc in pcs[:count]) and not any(pcs[count:]),
            "empty/malformed/overflowed stack or nonzero padding")
    threads[tid] += 1
    depths.append(count)
require(threads == expected_threads, "stack/fixture thread mismatch")
require(one(records, "STACK_COUNTS") == ["STACK_COUNTS", "4", str(sum(depths))],
        "stack totals")
print(f"PASS: four bounded raw user stacks across two fixture threads; "
      f"nonzero depths={depths}; stop/drain/close/reap complete")
