#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify controller quality, independent raw records and non-owning target survival."""

from collections import Counter
from pathlib import Path
import sys


def require(condition, message):
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def load(path):
    return [line.split("\t") for line in path.read_text().splitlines() if line]


def one(rows, tag):
    found = [row for row in rows if row[0] == tag]
    require(len(found) == 1, f"expected one {tag}")
    return found[0]


def fields(row):
    parts = [field.split("=", 1) for field in row[1:]]
    require(all(len(part) == 2 for part in parts), "malformed report")
    result = dict(parts)
    require(len(result) == len(parts), "duplicate report key")
    return result


if len(sys.argv) != 4:
    raise SystemExit("usage: verify_native_capture.py results-directory uid gid")
root = Path(sys.argv[1]); uid, gid = sys.argv[2:4]
for build in ("native_capture", "native_program", "native_event_decoder", "dtrace_session", "unit", "runtime",
              "controlled_capture_fixture", "unmarked_syscall_fixture", "syscall_fixture", "program-unit", "decoder-unit"):
    require(not (root / f"{build}-build.stdout").read_text() and
            not (root / f"{build}-build.stderr").read_text(), f"{build}: build diagnostics")
for name, count in (("native_capture", 40), ("native_program", 19), ("native_event_decoder", 64)):
    require(int((root / f"{name}-unit.status").read_text()) == 0 and
            not (root / f"{name}-unit.stderr").read_text() and
            (root / f"{name}-unit.stdout").read_text().startswith(f"PASS: {count} "), f"{name}: unit checks")
profiles = ("normal", "self", "cancel", "sigint", "sigterm", "incomplete", "fault", "drop", "limit", "capacity",
            "abandon", "option", "compile", "enable", "go", "work", "stop", "denied")
for profile in profiles:
    directory = root / profile
    require(int((directory / "exit-status").read_text()) == 0 and not (directory / "stderr").read_text(), f"{profile}: harness failure")
    rows = load(directory / "records.tsv")
    if profile == "denied":
        require(len(rows) == 1 and len(rows[0]) == 2 and rows[0][0] == "DENIED" and rows[0][1].startswith("open:"), "denied stage")
        print("PASS: denied; no successful handle open")
        continue
    rounds, current = {}, None
    for row in rows:
        if row[0] == "ROUND":
            require(len(row) == 2 and int(row[1]) not in rounds, "invalid round")
            current = int(row[1]); rounds[current] = []
        elif row[0] != "DESTRUCTOR_TEST":
            require(current is not None, "data outside round")
            rounds[current].append(row)
    require(rounds.keys() == ({1, 2} if profile == "normal" else {1}), "missing rounds")
    if profile == "normal":
        require(one(rows, "DESTRUCTOR_TEST") == ["DESTRUCTOR_TEST", "opens=1", "closes=1", "stops=1", "passed=1"], "destructor cleanup")
    for number, output in rounds.items():
        values = fields(one(output, "CONTROLLER_REPORT"))
        require(values.pop("profile") == profile, "wrong profile")
        s = {key: int(value) for key, value in values.items()}
        keys = {"round", "target", "monitor", "actual_monitor", "fixture", "phase", "reason", "complete", "requested", "cancel",
                "opened", "started", "stopped", "drained", "closed", "failed", "discarded", "probes", "records", "zero", "errors", "drops",
                "events", "alive", "child", "blocked", "signal", "cancel_ns", "opens", "closes", "stops", "real_stops", "injected", "self_calls"}
        require(s.keys() == keys and all(value >= 0 for value in s.values()), "controller report fields")
        require(s["round"] == number and s["monitor"] == s["actual_monitor"] > 0 and s["fixture"] > 0 and
                s["target"] == s["monitor" if profile == "self" else "fixture"], "automatic monitor/target identity")
        require(s["child"] == 0 and s["opened"] == s["closed"] == 1 and s["opens"] == s["closes"] == number,
                "target exit or handle accounting")
        d = {key: int(value) for key, value in fields(one(output, "DECODER_REPORT")).items()}
        require(d.keys() == {"present", "finalized", "complete", "completed", "cancelled", "incomplete", "issue", "start", "end"} and d["present"] == 1,
                "decoder report fields")
        require(s["events"] == d["completed"] + d["cancelled"] + d["incomplete"], "event totals")
        require(s["phase"] == (4 if profile == "abandon" else 3) and d["finalized"] == (profile != "abandon"), "terminal phase/finalization")
        success = profile in {"normal", "self"}
        cancelled = profile in {"cancel", "sigint", "sigterm"}
        reason = 1 if success else 2 if cancelled else 4 if profile == "abandon" else 3
        require(s["reason"] == reason and s["complete"] == success and s["cancel"] == cancelled, "false end reason/quality")
        diagnostics = [row for row in output if row[0] == "DIAGNOSTIC"]
        require(bool(diagnostics) == (reason == 3), "missing/unexpected diagnostic")
        if diagnostics:
            prefix = {"option": "setup:", "compile": "compile:", "enable": "enable:", "go": "go:",
                      "work": "work:", "stop": "stop:", "limit": "callback: batch byte limit",
                      "capacity": "pending correlation capacity", "fault": "DTrace runtime error",
                      "drop": "DTrace dropped", "incomplete": "capture has unresolved"}[profile]
            require(len(diagnostics) == 1 and diagnostics[0][1].startswith(prefix), "wrong failure stage")
        notices = [row for row in output if row[0] == "NOTICE"]
        require(all(len(row) == 3 and row[1] in {"0", "1"} for row in notices) and
                sum(int(row[2]) for row in notices if row[1] == "0") == s["errors"] and
                sum(int(row[2]) for row in notices if row[1] == "1") == s["drops"], "lost notices")
        if profile in {"normal", "self", "cancel", "sigint", "sigterm", "incomplete", "fault", "drop", "capacity"}:
            require(s["started"] == s["stopped"] == s["drained"] == 1 and s["failed"] == s["discarded"] == 0, "orderly lifecycle")
        elif profile in {"option", "compile", "enable", "go"}:
            require(s["started"] == s["stopped"] == s["drained"] == s["discarded"] == 0 and s["failed"] == s["alive"] == 1, "startup failure cleanup")
        else:
            require(s["started"] == s["stopped"] == s["discarded"] == s["alive"] == 1 and s["drained"] == 0 and
                    s["failed"] == (profile != "abandon"), "fatal/abandoned lifecycle")
        require(s["injected"] == (profile in {"compile", "enable", "go", "work", "stop"}), "failure injection not exercised")
        require(s["stops"] == (2 if profile == "stop" else 0 if profile in {"option", "compile", "enable", "go"} else number) and
                s["real_stops"] == (0 if profile in {"option", "compile", "enable", "go"} else number), "stop cleanup path")
        if profile == "fault": require(s["errors"] > 0 and s["drops"] == 0, "real fault absent")
        elif profile == "drop": require(s["drops"] > 0 and s["errors"] == 0, "drop case unverified")
        else: require(s["errors"] == s["drops"] == 0, "unexpected native fault/drop")
        if profile == "capacity": require(d["issue"] == 3, "capacity failure hidden")
        if profile in {"option", "compile", "enable", "go", "work", "stop", "limit"}:
            require(d["issue"] == 6 and s["events"] == 0, "fatal failure falsely decoded complete data")
        if profile == "self": require(s["events"] == 0 and s["self_calls"] == 3 and d["complete"] == 1, "self exclusion not exercised")
        else: require(s["self_calls"] == 0, "unexpected self workload")
        entries, returns, events = {}, {}, {}
        boundaries = {}
        for row in output:
            if row[0] == "BOUNDARY":
                require(len(row) == 4 and row[1] not in boundaries and int(row[2]) == s["target"], "boundary identity/duplicates")
                boundaries[row[1]] = int(row[3])
            if row[0] not in {"RAW_ENTRY", "RAW_RETURN", "EVENT"}: continue
            require(len(row) == {"RAW_ENTRY": 8, "RAW_RETURN": 11, "EVENT": 23}[row[0]] and
                    int(row[1]) == s["target"] and int(row[2]) > 0 and row[3] in {"openat", "read", "write"}, "raw/event shape/scope")
            key = (row[1], row[2], row[3], int(row[4]))
            target = entries if row[0] == "RAW_ENTRY" else returns if row[0] == "RAW_RETURN" else events
            require(key not in target, "duplicate record/event")
            target[key] = row
        require(len(events) == s["events"], "missing typed event")
        states = Counter()
        observed = Counter()
        for key, event in events.items():
            entry, returned = entries.get(key), returns.get(key)
            state = int(event[5]); states[state] += 1
            require(state in {0, 1, 2} and (event[6] != "1" or entry is not None) and
                    (event[7] != "1" or returned is not None), "fabricated entry/return evidence")
            if event[8] == "1":
                require(entry is not None and "BEGIN" in boundaries and int(event[9]) == key[3] - boundaries["BEGIN"] >= 0,
                        "wrong relative clock/reference")
                if "END" in boundaries: require(key[3] <= boundaries["END"], "entry beyond END")
            require(event[16:18] == (returned[6:8] if event[7] == "1" else ["0", "0"]), "return diagnostics changed")
            require(event[20] == ("1" if key[2] == "openat" else "0") and
                    event[21] == ("1" if key[2] == "openat" and len(event[22]) == 64 else "0"), "path presence/limit")
            if state == 0:
                require(entry is not None and returned is not None and event[6:9] == ["1"] * 3 and
                        event[10] == event[12] == event[14] == "1" and
                        [event[11], event[13], event[15]] == returned[5:8], "completed fields mismatch")
                require(event[18:20] == entry[5:7] == returned[8:10] and event[22] == entry[7] == returned[10], "typed arguments mismatch")
                if "END" in boundaries: require(int(event[11]) <= boundaries["END"] - key[3], "duration beyond END")
                observed[(key[0], key[1], key[2], int(event[18]), int(event[19]), int(event[13]), int(event[15]), event[22])] += 1
            else:
                require(event[10:16] == ["0"] * 6, "fabricated unresolved duration/result/errno")
        require(states[0] == d["completed"] and states[1] == d["cancelled"] and states[2] == d["incomplete"], "state totals")
        if profile in {"normal", "self", "cancel", "sigint", "sigterm", "incomplete", "fault"}:
            require(boundaries.keys() == {"BEGIN", "END"} and d["start"] == boundaries["BEGIN"] < d["end"] == boundaries["END"] and d["issue"] == -1,
                    "valid capture lost/changed clock boundary")
            require(set(entries) | set(returns) == set(events), "lost/invented paired observation")
        if success:
            fixture = load(directory / f"run{number}" / "fixture.tsv")
            pid = str(s["fixture"])
            require(one(fixture, "IDENTITY") == ["IDENTITY", pid, uid, gid] and
                    one(fixture, "FIXTURE") == ["FIXTURE", pid, "6", "0"], "workload fixture result")
            expected = Counter((row[1], row[2], row[3], int(row[5]), int(row[6]), int(row[7]), int(row[8]), row[9][:64] if row[3] == "openat" else "-")
                               for row in fixture if row[0] == "EXPECT")
            require(profile == "self" or not (expected - observed), "known workload calls lost/changed")
            require(d["complete"] == 1 and d["cancelled"] == d["incomplete"] == 0, "normal final quality")
        if profile in {"cancel", "sigint", "sigterm", "incomplete", "fault"}:
            fixture = load(directory / "run1" / "fixture.tsv")
            expected, result = one(fixture, "BLOCK_EXPECT"), one(fixture, "BLOCK_RESULT")
            require(s["alive"] == s["blocked"] == 1 and expected[1] == str(s["fixture"]) and expected[4:6] == [uid, gid] and
                    result[1:3] == expected[1:3] and result[3:] == ["1", "0"], "target did not survive and complete its read")
            unresolved = [row for row in events.values() if row[5] != "0"]
            require(len(unresolved) == 1 and unresolved[0][1:3] == expected[1:3] and unresolved[0][3] == "read" and
                    unresolved[0][6:9] == ["1", "0", "1"] and unresolved[0][16:18] == ["0", "0"] and
                    unresolved[0][18:20] == [expected[3], "1"] and unresolved[0][5] == ("1" if cancelled else "2"), "unresolved read fabricated or relabelled")
            if profile == "fault":
                fault = one(fixture, "FAULT_EXPECT")
                require(fault[1:3] == expected[1:3] and fault[3] == "-1" and int(fault[4]) > 0, "fault fixture oracle")
            else: require(0 < s["cancel_ns"] < 2000000000, "stop/cancel latency bound")
        require(s["signal"] == (2 if profile == "sigint" else 15 if profile == "sigterm" else 0), "signal evidence")
        print(f"PASS: {profile} round {number}; outcome, final quality, owned data and target survival")
