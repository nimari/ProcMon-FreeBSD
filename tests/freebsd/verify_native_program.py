#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check generated source, real PID/syscall exclusion and independent workload subsets."""

from collections import Counter
from pathlib import Path
import re
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


if len(sys.argv) != 4:
    raise SystemExit("usage: verify_native_program.py results-directory uid gid")
root = Path(sys.argv[1])
uid, gid = sys.argv[2:4]
for build in ("program", "unit", "decoder", "session", "capture", "unmarked", "fixture", "decoder-unit"):
    require(not (root / f"{build}-build.stdout").read_text() and
            not (root / f"{build}-build.stderr").read_text(), f"{build}: build diagnostics")
for test, count in (("unit", 19), ("decoder-unit", 64)):
    require(int((root / f"{test}.status").read_text()) == 0 and not (root / f"{test}.stderr").read_text() and
            (root / f"{test}.stdout").read_text().startswith(f"PASS: {count} "), f"{test}: native checks")
profiles = {"openat": 1, "read": 2, "write": 4, "openat-read": 3, "openat-write": 5,
            "read-write": 6, "all": 7, "unmarked": 7, "self": 7}
for profile, mask in profiles.items():
    directory = root / profile
    require(int((directory / "exit-status").read_text()) == 0 and not (directory / "stderr").read_text(),
            f"{profile}: harness failed")
    rows = load(directory / "records.tsv")
    parts = [field.split("=", 1) for field in one(rows, "PROGRAM_REPORT")[1:]]
    require(all(len(part) == 2 for part in parts), "report shape")
    values = dict(parts)
    require(len(values) == len(parts) and values.pop("profile") == profile, "report profile/duplicates")
    status = {key: int(value) for key, value in values.items()}
    keys = {"mask", "target", "monitor", "fixture", "noise", "child_a", "child_b", "monitor_calls", "complete",
            "events", "started", "stopped", "drained", "closed", "failed", "discarded", "probes", "records", "zero", "errors", "drops"}
    require(status.keys() == keys and all(value >= 0 for value in status.values()), "report fields")
    require(status["mask"] == mask and len({status["monitor"], status["fixture"], status["noise"]}) == 3 and
            all(status[key] > 0 for key in ("target", "monitor", "fixture", "noise")), "PID/filter identity")
    require(status["target"] == status["monitor" if profile == "self" else "fixture"], "wrong target PID")
    require(all(status[key] == 1 for key in ("complete", "started", "stopped", "drained", "closed")) and
            all(status[key] == 0 for key in ("failed", "discarded", "errors", "drops", "child_a", "child_b")) and
            status["monitor_calls"] == 6, "capture/fixture/monitor control failure")
    selected = {name for bit, name in enumerate(("openat", "read", "write")) if mask & (1 << bit)}
    source = (directory / "generated-source.txt").read_text()
    probes = re.findall(r"syscall:([^:]+):([^:]+):(entry|return)\n/([^\n]+)/", source)
    require(len(probes) == 2 * len(selected) and
            {(module, name, kind) for module, name, kind, _ in probes} ==
            {("freebsd", name, kind) for name in selected for kind in ("entry", "return")}, "wrong generated probe set")
    predicate = f"pid == {status['target']} && pid != {status['monitor']}"
    for _, name, kind, expression in probes:
        require(expression == predicate + (f" && self->pm_{name}_seen" if kind == "return" else ""),
                "PID/self/observed-entry predicate changed")
    require("getpgid" not in source and "active" not in source and "$" not in source and
            source.count("dtrace:::BEGIN") == source.count("dtrace:::END") == 1, "marker gating/macros/boundaries")
    fixtures = {}
    for role, pid_key in (("target", "fixture"), ("noise", "noise")):
        fixture = load(directory / role / "fixture.tsv")
        pid = str(status[pid_key])
        count = 6 if profile == "unmarked" else 16
        require(one(fixture, "IDENTITY") == ["IDENTITY", pid, uid, gid] and
                one(fixture, "FIXTURE") == ["FIXTURE", pid, str(count), "0"], f"{role}: identity/result")
        expected = [row for row in fixture if row[0] == "EXPECT"]
        require(len(expected) == count and all(len(row) == 10 and row[1] == pid for row in expected),
                f"{role}: oracle records")
        fixtures[role] = expected
    boundaries = [row for row in rows if row[0] == "BOUNDARY"]
    require(len(boundaries) == 2 and {row[1] for row in boundaries} == {"BEGIN", "END"} and
            all(len(row) == 4 and int(row[2]) == status["target"] for row in boundaries), "boundary identity")
    times = {row[1]: int(row[3]) for row in boundaries}
    start, end = times["BEGIN"], times["END"]
    require(0 < start < end, "raw clock window")
    entries, returns, events = {}, {}, {}
    target_threads = {row[2] for row in fixtures["target"]}
    noise_threads = {row[2] for row in fixtures["noise"]}
    require(all(row[0] in {"BOUNDARY", "RAW_ENTRY", "RAW_RETURN", "EVENT", "PROGRAM_REPORT"} for row in rows),
            "unknown capture row")
    for row in rows:
        if row[0] not in {"RAW_ENTRY", "RAW_RETURN", "EVENT"}: continue
        require(len(row) == {"RAW_ENTRY": 8, "RAW_RETURN": 11, "EVENT": 14}[row[0]], "raw/event shape")
        require(int(row[1]) == status["target"] and row[3] in selected and int(row[2]) > 0,
                "monitor/noise/unselected syscall leaked through filtering")
        require(row[2] in target_threads and row[2] not in noise_threads, "unselected thread leaked into capture")
        key = (row[1], row[2], row[3], int(row[4]))
        target = entries if row[0] == "RAW_ENTRY" else returns if row[0] == "RAW_RETURN" else events
        require(key not in target, "duplicate pair key")
        target[key] = row
    require(entries.keys() == returns.keys() == events.keys() and len(events) == status["events"] and
            status["probes"] == 2 * len(events) + 2 and status["records"] == 15 * len(events) + 4,
            "missing/invented entry/return/event or callback counts")
    observed = Counter()
    for key, event in events.items():
        entry, returned = entries[key], returns[key]
        raw_time = int(entry[4])
        require(start <= raw_time <= end and int(event[5]) == raw_time - start and
                event[6:9] == returned[5:8] and int(event[6]) <= end - raw_time, "time/result/errno mismatch")
        require(event[9:11] == entry[5:7] == returned[8:10] and event[13] == entry[7] == returned[10] and
                event[11] == ("1" if key[2] == "openat" else "0") and
                event[12] == ("1" if key[2] == "openat" and len(entry[7]) == 64 else "0"), "typed arguments mismatch")
        observed[(event[1], event[2], event[3], int(event[9]), int(event[10]),
                  int(event[7]), int(event[8]), event[13])] += 1
    expected = Counter()
    if profile == "self":
        require(not events and status["zero"] == 0, "monitor target was not excluded")
    else:
        for row in fixtures["target"]:
            if row[3] not in selected: continue
            expected[(row[1], row[2], row[3], int(row[5]), int(row[6]), int(row[7]), int(row[8]),
                      row[9][:64] if row[3] == "openat" else "-")] += 1
        require(expected and not (expected - observed), "selected fixture call missing/changed")
        require({key[2] for key in events} == selected, "positive syscall filter not exercised")
    print(f"PASS: {profile}; {len(events)} captured pairs, {sum(expected.values())} selected oracle calls; "
          "monitor/noise excluded and capture complete")
