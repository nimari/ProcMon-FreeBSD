#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify clock anchors and controlled, real SIGINT/SIGTERM cleanup."""

from pathlib import Path
import sys


def require(condition, message):
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def rows(path):
    return [line.split("\t") for line in path.read_text().splitlines() if line]


def one(data, tag):
    matches = [row for row in data if row[0] == tag]
    require(len(matches) == 1, f"expected one {tag}")
    return matches[0]


def status(directory, mode):
    data = rows(directory / "api-status.tsv")
    require(len(data) == 1 and data[0][0] == "API_STATUS", f"{mode}: status")
    parts = [part.split("=", 1) for part in data[0][1:]]
    wanted = {"pid", "mode", "probes", "records", "zero_records", "entries",
              "returns", "errors", "drops", "schema", "started", "stopped",
              "drained", "closed", "reaped", "child_status", "startup_error",
              "blocked", "signal_sent", "signal_seen", "cancel_elapsed_ns"}
    require(all(len(pair) == 2 for pair in parts), f"{mode}: status pairs")
    values = dict(parts)
    require(len(parts) == len(values) and values.keys() == wanted and
            values.pop("mode") == mode, f"{mode}: status fields")
    values = {key: int(value) for key, value in values.items()}
    require(all(value >= 0 for value in values.values()), f"{mode}: counters")
    require(values["pid"] > 0, f"{mode}: PID")
    require(all(values[key] == 1 for key in
                ("started", "stopped", "drained", "closed", "reaped")),
            f"{mode}: incomplete lifecycle")
    require(all(values[key] == 0 for key in
                ("errors", "drops", "schema", "startup_error")),
            f"{mode}: unexpected failure")
    records = rows(directory / "records.tsv")
    require(one(records, "BEGIN") == ["BEGIN", str(values["pid"])] and
            one(records, "END") == ["END"], f"{mode}: missing boundary records")
    return values, records


if len(sys.argv) != 4:
    raise SystemExit("usage: verify_clock_signal.py results-directory uid gid")
root = Path(sys.argv[1])
uid, gid = map(int, sys.argv[2:4])
require(uid != 0, "nonroot fixture identity required")
directory = root / "clock"
summary, records = status(directory, "clock")
require(int((directory / "exit-status").read_text()) == 0 and
        not (directory / "stderr").read_text(), "clock: command result")
require(summary["entries"] == summary["returns"] == 8 and
        summary["probes"] == 19 and summary["records"] == 84 and
        summary["zero_records"] == 16 and summary["child_status"] == 0,
        "clock: callback counts")
require(all(summary[key] == 0 for key in
            ("blocked", "signal_sent", "signal_seen", "cancel_elapsed_ns")),
        "clock: unexpected cancellation")
require(all(row[0] in {"BEGIN", "END", "CLOCK_ENTRY", "CLOCK_RETURN", "TARGET_EXIT"}
            for row in records), "clock: unexpected records")
require(one(records, "TARGET_EXIT") == ["TARGET_EXIT", str(summary["pid"]), "0"],
        "clock: fixture exit record")
observed = rows(directory / "fixture.tsv")
fixture = one(observed, "CLOCK_FIXTURE")
require(len(fixture) == 6 and list(map(int, fixture[1:5])) ==
        [summary["pid"], 8, uid, gid], "clock: fixture summary")
expected = [row for row in observed if row[0] == "CLOCK_EXPECT"]
require(len(observed) == 9 and len(expected) == 8, "clock: expected samples")
entries, returns = {}, {}
for row in records:
    if row[0] == "CLOCK_ENTRY":
        require(len(row) == 6, "clock: entry shape")
        key = tuple(map(int, (row[1], row[2], row[4])))
        require(key not in entries, "clock: duplicate entry")
        entries[key] = row
    elif row[0] == "CLOCK_RETURN":
        require(len(row) == 8, "clock: return shape")
        key = tuple(map(int, (row[1], row[2], row[6])))
        require(key not in returns, "clock: duplicate return")
        returns[key] = row
require(len(entries) == len(returns) == 8 and entries.keys() == returns.keys(),
        "clock: unmatched records")
intervals, cpus = [], set()
previous_user = previous_kernel = 0
for index, row in enumerate(expected):
    require(len(row) == 9, "clock: expectation shape")
    pid, tid, sequence, cpu, before, after, result, error = map(int, row[1:])
    require(pid == summary["pid"] and sequence == index and before <= after,
            "clock: identity or bracket")
    key = (pid, tid, -1000 - index)
    require(key in entries, "clock: missing identified sample")
    entry, returned = entries[key], returns[key]
    began, ended = int(entry[3]), int(returned[3])
    require(int(entry[5]) == int(returned[7]) == cpu, "clock: CPU mismatch")
    require((int(returned[4]), int(returned[5])) == (result, error),
            "clock: syscall result mismatch")
    require(before > previous_user and began > previous_kernel and ended > began,
            "clock: nonmonotonic timestamps")
    previous_user, previous_kernel = after, ended
    low, high = ended - after, began - before
    require(low <= high, "clock: syscall interval exceeds userspace bracket")
    intervals.append((low, high, cpu))
    cpus.add(cpu)
require(len(cpus) == int(fixture[5]), "clock: missing CPU samples")
low, high = max(item[0] for item in intervals), min(item[1] for item in intervals)
classification = ("DIRECT" if low <= 0 <= high else
                  "OFFSET_REQUIRED" if low <= high else "NO_CONSTANT_OFFSET")
print(f"Clock classification: {classification}; offset intersection [{low}, {high}] ns; CPUs={sorted(cpus)}")
for cpu in sorted(cpus):
    subset = [(a, b) for a, b, found_cpu in intervals if found_cpu == cpu]
    print(f"CPU {cpu}: offset intersection [{max(a for a, b in subset)}, {min(b for a, b in subset)}] ns")
print("PASS: eight identified clock brackets and syscall results; classification is a finding, not a conversion policy")

for mode, signal_number in (("sigint", 2), ("sigterm", 15)):
    directory = root / mode
    summary, records = status(directory, mode)
    require(int((directory / "exit-status").read_text()) == 128 + signal_number,
            f"{mode}: consumer exit status")
    require((directory / "stderr").read_text() == f"API_CANCEL\tsignal={signal_number}\n",
            f"{mode}: cancellation diagnostic")
    require(summary["signal_sent"] == summary["signal_seen"] == signal_number,
            f"{mode}: signal delivery not observed")
    require(summary["blocked"] == summary["entries"] == 1 and summary["returns"] <= 1,
            f"{mode}: missing blocked target")
    require(summary["probes"] == 4 + summary["returns"] and
            summary["records"] == 10 + 5 * summary["returns"] and
            summary["zero_records"] == 1, f"{mode}: callback counts")
    require(summary["child_status"] == 137 and
            0 < summary["cancel_elapsed_ns"] < 2000000000,
            f"{mode}: child cleanup or two-second cancellation bound")
    observed = rows(directory / "fixture.tsv")
    require(len(observed) == 1, f"{mode}: unexpected fixture output")
    expected = one(observed, "BLOCK_EXPECT")
    require(len(expected) == 6 and int(expected[1]) == summary["pid"] and
            list(map(int, expected[4:])) == [uid, gid], f"{mode}: fixture identity")
    blocked = one(records, "BLOCKED")
    require(len(blocked) == 6 and blocked[1:3] == expected[1:3] and
            blocked[4] == expected[3] and blocked[5] == "1", f"{mode}: wrong read")
    marker = one(records, "START")
    require(len(marker) == 3 and marker[1] == expected[1] and
            int(marker[2]) <= int(blocked[3]),
            f"{mode}: read before marker")
    require(all(row[0] in {"BEGIN", "START", "BLOCKED", "BLOCK_RETURN", "END"}
                for row in records), f"{mode}: unexpected capture")
    completed = [row for row in records if row[0] == "BLOCK_RETURN"]
    require(len(completed) == summary["returns"], f"{mode}: return count")
    for row in completed:
        require(len(row) == 6 and row[1:3] == blocked[1:3] and
                int(row[3]) >= int(blocked[3]), f"{mode}: invalid partial return")
        raw_error = int(row[5])
        require(0 <= raw_error < 2**64, f"{mode}: invalid raw errno bits")
        signed_error = raw_error if raw_error < 2**63 else raw_error - 2**64
        print(f"{mode}: killed-target return is diagnostic only; raw errno interpreted as signed = {signed_error}")
    print(f"PASS: {mode}, signal received; stop/drain/close/reap in {summary['cancel_elapsed_ns']} ns")
