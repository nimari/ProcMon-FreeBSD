#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independently compare raw records, normalized times, and validity flags."""

from pathlib import Path
import subprocess
import sys
import tempfile


def require(condition, message):
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def load(path):
    return [row.split("\t") for row in path.read_text().splitlines() if row]


def one(rows, tag):
    matches = [row for row in rows if row[0] == tag]
    require(len(matches) == 1, f"expected one {tag}")
    return matches[0]


if len(sys.argv) != 4:
    raise SystemExit("usage: verify_session_contract.py results-directory uid gid")
root = Path(sys.argv[1])
uid, gid = sys.argv[2:4]
for mode, number in (("normal", 0), ("sigint", 2), ("sigterm", 15)):
    directory = root / f"contract-{mode}"
    status = one(load(directory / "api-status.tsv"), "API_STATUS")
    pairs = [part.split("=", 1) for part in status[1:]]
    require(all(len(pair) == 2 for pair in pairs), f"{mode}: malformed status")
    values = dict(pairs)
    require(len(values) == len(pairs) and values.pop("mode") == mode, f"{mode}: mode")
    summary = {key: int(value) for key, value in values.items()}
    require(all(value >= 0 for value in summary.values()), f"{mode}: negative counters")
    require(all(summary[key] == 1 for key in
                ("started", "stopped", "drained", "closed", "reaped")),
            f"{mode}: lifecycle")
    require(all(summary[key] == 0 for key in ("errors", "drops", "schema", "startup_error")),
            f"{mode}: capture failure")
    require(int((directory / "exit-status").read_text()) == (128 + number if number else 0),
            f"{mode}: exit status")
    require((directory / "stderr").read_text() == (f"API_CANCEL\tsignal={number}\n" if number else ""),
            f"{mode}: diagnostics")
    rows = load(directory / "records.tsv")
    allowed = {"BEGIN", "END", "START", "STOP", "TARGET_EXIT", "RAW_ENTRY",
               "RAW_RETURN", "SESSION", "CONTRACT_EVENT", "CONTRACT_COUNTS"}
    require(all(row[0] in allowed for row in rows), f"{mode}: unknown output")
    session = one(rows, "SESSION")
    require(len(session) == 7 and session[1:4] ==
            ["1", "freebsd-native", "dtrace-session-ns"] and
            int(session[4]) == summary["pid"], f"{mode}: session metadata")
    start, end = map(int, session[5:7])
    require(0 < start < end, f"{mode}: session bounds")
    require(one(rows, "BEGIN") == ["BEGIN", session[4]] and one(rows, "END") == ["END"],
            f"{mode}: boundaries")
    entries, returns, events = {}, {}, {}
    for row in rows:
        if row[0] in {"RAW_ENTRY", "RAW_RETURN"}:
            require(len(row) == (8 if row[0] == "RAW_ENTRY" else 11), f"{mode}: raw shape")
            require(int(row[1]) == summary["pid"], f"{mode}: raw PID")
            key = (row[1], row[2], row[3], int(row[4]))
            target = entries if row[0] == "RAW_ENTRY" else returns
            require(key not in target, f"{mode}: duplicate raw record")
            target[key] = row
        elif row[0] == "CONTRACT_EVENT":
            require(len(row) == 18 and row[1] == "1", f"{mode}: event shape/version")
            require(int(row[2]) == summary["pid"] and row[6] == row[14] == "1",
                    f"{mode}: entry/timestamp validity")
            timestamp = int(row[7])
            require(0 <= timestamp <= end - start, f"{mode}: invalid relative timestamp")
            key = (row[2], row[3], row[4], start + timestamp)
            require(key not in events, f"{mode}: duplicate normalized event")
            events[key] = row
    require(entries.keys() == events.keys(), f"{mode}: missing or invented event")
    require(len(entries) == summary["entries"] and len(returns) == summary["returns"],
            f"{mode}: raw counts")
    counts = one(rows, "CONTRACT_COUNTS")
    require(counts == (["CONTRACT_COUNTS", "0", "1", "0"] if number else
                       ["CONTRACT_COUNTS", "16", "0", "0"]), f"{mode}: state totals")
    for key, event in events.items():
        entry = entries[key]
        returned = returns.get(key)
        require(int(event[7]) == int(entry[4]) - start, f"{mode}: wrong clock domain")
        require(event[15] == ("1" if returned else "0"), f"{mode}: invented return")
        require(list(map(int, event[16:18])) ==
                ([int(returned[6]), int(returned[7])] if returned else [0, 0]),
                f"{mode}: lost diagnostic bits")
        if number:
            require(event[5] == "cancelled" and event[8:14] == ["0"] * 6,
                    f"{mode}: fabricated completed fields or leaked errno sentinel")
            if returned:
                require(int(returned[7]) > 2**31 - 1, f"{mode}: ordinary return misclassified")
        else:
            require(returned is not None and event[5] == "completed" and
                    event[8] == event[10] == event[12] == "1", "normal: validity")
            require(list(map(int, (event[9], event[11], event[13]))) ==
                    list(map(int, returned[5:8])), "normal: changed duration/result/errno")
            require(int(event[9]) <= end - int(entry[4]), "normal: duration outside session")
    if number:
        require(len(events) == 1 and summary["blocked"] == 1 and
                summary["signal_sent"] == summary["signal_seen"] == number and
                summary["child_status"] == 137 and
                0 < summary["cancel_elapsed_ns"] < 2000000000,
                f"{mode}: controlled cancellation")
        expected = one(load(directory / "fixture.tsv"), "BLOCK_EXPECT")
        key, entry = next(iter(entries.items()))
        require(entry[1:3] == expected[1:3] and entry[3] == "read" and
                entry[5] == expected[3] and entry[6] == "1" and
                expected[4:6] == [uid, gid], f"{mode}: wrong blocked fixture")
    else:
        require(len(events) == 16 and summary["child_status"] == 0 and
                summary["records"] == 252 and summary["probes"] == 37,
                "normal: complete typed delivery")
        # Reuse the unchanged, independent workload verification on the raw input.
        readme = Path(__file__).with_name("README.md").read_text()
        baseline = readme.split("EXPECTED_GID <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        raw = [row for row in rows if row[0] not in {"SESSION", "CONTRACT_EVENT", "CONTRACT_COUNTS"}]
        for row in raw:
            row[0] = {"RAW_ENTRY": "ENTRY", "RAW_RETURN": "EVENT"}.get(row[0], row[0])
        with tempfile.TemporaryDirectory(prefix="procmon-contract-verify-") as temporary:
            combined = Path(temporary) / "capture.tsv"
            combined.write_text((directory / "fixture.tsv").read_text() +
                                "\n".join("\t".join(row) for row in raw) + "\n")
            result = subprocess.run([sys.executable, "-", str(combined),
                                     str(directory / "stderr"), "0", uid, gid],
                                    input=baseline, text=True)
            require(result.returncode == 0, "normal: independent workload comparison")
    print(f"PASS: contract-{mode}; events={len(events)}; same-domain relative times; explicit validity/state")
