#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check streaming native events against raw copied records and fixture results."""

from pathlib import Path
import subprocess
import sys
import tempfile


def require(condition, message):
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def one(rows, tag):
    matches = [row for row in rows if row[0] == tag]
    require(len(matches) == 1, f"expected one {tag}")
    return matches[0]


def counters(row):
    parts = [field.split("=", 1) for field in row[1:]]
    require(all(len(part) == 2 for part in parts), "malformed counters")
    values = dict(parts)
    require(len(values) == len(parts), "duplicate counters")
    return values


if len(sys.argv) != 4:
    raise SystemExit("usage: verify_native_event_decoder.py results-directory uid gid")
root = Path(sys.argv[1])
uid, gid = sys.argv[2:4]
legacy = subprocess.run([sys.executable, str(Path(__file__).with_name("verify_dtrace_session.py")),
                         str(root), uid, gid])
require(legacy.returncode == 0, "default session harness regressions")
for build in ("decoder", "unit", "capture"):
    require(not (root / f"{build}-build.stdout").read_text() and
            not (root / f"{build}-build.stderr").read_text(), f"{build}: build diagnostics")
require(int((root / "unit.status").read_text()) == 0 and not (root / "unit.stderr").read_text() and
        (root / "unit.stdout").read_text().startswith("PASS: 64 "), "native decoder unit checks")
readme = Path(__file__).with_name("README.md").read_text()
baseline = readme.split("EXPECTED_GID <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
for mode in ("normal", "sigint", "sigterm", "drop"):
    directory = root / f"decoded-{mode}"
    require(int((directory / "exit-status").read_text()) == 0 and
            not (directory / "stderr").read_text(), f"decoded-{mode}: harness failure")
    rows = [line.split("\t") for line in (directory / "records.tsv").read_text().splitlines() if line]
    rounds, current = {}, None
    for row in rows:
        if row[0] == "ROUND":
            require(len(row) == 2 and int(row[1]) not in rounds, "duplicate round")
            current = int(row[1]); rounds[current] = []
        elif row[0] != "DESTRUCTOR_TEST":
            require(current is not None, "data outside round")
            rounds[current].append(row)
    require(rounds.keys() == ({1, 2} if mode == "normal" else {1}), "missing decoded rounds")
    for number, output in rounds.items():
        status = counters(one(output, "SESSION_STATUS"))
        require(status.pop("mode") == mode, "wrong capture mode")
        status = {key: int(value) for key, value in status.items()}
        require(all(status[key] == 1 for key in ("opened", "started", "stopped", "drained", "closed", "reaped")) and
                status["failed"] == status["discarded"] == 0 and
                status["opens"] == status["closes"] == number, "decoded capture lifecycle")
        report = {key: int(value) for key, value in counters(one(output, "DECODER_REPORT")).items()}
        require(report.keys() == {"complete", "issue", "streamed", "errors", "drops"} and
                report["errors"] == status["errors"] and report["drops"] == status["drops"], "report/capture mismatch")
        session = one(output, "SESSION")
        require(len(session) == 7 and session[1:4] == ["1", "freebsd-native", "dtrace-session-ns"] and
                int(session[4]) == status["pid"], "session identity/domain")
        boundaries = {row[1]: row for row in output if row[0] == "RAW_BOUNDARY"}
        require(all(len(row) == 4 and row[2] == session[4] for row in boundaries.values()), "raw boundary identity")
        if mode == "drop":
            require(status["drops"] > 0 and status["errors"] == 0 and report["complete"] == 0,
                    "dropped capture falsely complete or drop test unverified")
            require(report["streamed"] <= len([row for row in output if row[0] == "CONTRACT_EVENT"]), "stream totals")
            print(f"PASS: decoded-drop; {status['drops']} real drops, complete=false, issue={report['issue']}")
            continue
        require(boundaries.keys() == {"BEGIN", "END"} and
                session[5:] == [boundaries["BEGIN"][3], boundaries["END"][3]], "decoder changed raw clock reference")
        start, end = map(int, session[5:])
        require(0 < start < end and report["issue"] == -1 and report["errors"] == report["drops"] == 0,
                "clock/report failure")
        entries, returns, events, arguments = {}, {}, {}, {}
        for row in output:
            if row[0] in {"RAW_ENTRY", "RAW_RETURN", "NATIVE_ARGUMENTS"}:
                require(len(row) == {"RAW_ENTRY": 8, "RAW_RETURN": 11, "NATIVE_ARGUMENTS": 10}[row[0]], "raw/argument shape")
                key = (row[1], row[2], row[3], int(row[4]))
                target = entries if row[0] == "RAW_ENTRY" else returns if row[0] == "RAW_RETURN" else arguments
                require(key not in target and row[1] == session[4], "duplicate/wrong-PID record")
                target[key] = row
            elif row[0] == "CONTRACT_EVENT":
                require(len(row) == 18 and row[1] == "1" and row[2] == session[4] and
                        row[6] == row[14] == "1", "event version/identity/entry validity")
                key = (row[2], row[3], row[4], start + int(row[7]))
                require(key not in events and 0 <= int(row[7]) <= end - start, "event identity/time")
                events[key] = row
        require(entries.keys() == events.keys() == arguments.keys(), "missing/invented/cross-paired event")
        for key, event in events.items():
            entry, returned, args = entries[key], returns.get(key), arguments[key]
            require(int(event[7]) == int(entry[4]) - int(boundaries["BEGIN"][3]), "wrong timestamp domain/base")
            require(args[5:7] == entry[5:7] and args[9] == entry[7] and
                    args[7] == ("1" if key[2] == "openat" else "0") and
                    args[8] == ("1" if key[2] == "openat" and len(entry[7]) == 64 else "0"), "typed argument/path mismatch")
            require(event[15] == ("1" if returned else "0") and list(map(int, event[16:18])) ==
                    ([int(returned[6]), int(returned[7])] if returned else [0, 0]), "return evidence/diagnostics")
            if mode == "normal":
                require(returned is not None and event[5] == "completed" and event[8] == event[10] == event[12] == "1" and
                        list(map(int, (event[9], event[11], event[13]))) == list(map(int, returned[5:8])) and
                        int(event[9]) <= end - int(entry[4]), "duration/result/errno mismatch")
            else:
                require(event[5] == "cancelled" and event[8:14] == ["0"] * 6 and
                        (returned is None or int(returned[7]) > 2**31 - 1), "fabricated cancellation completion")
        counts = one(output, "CONTRACT_COUNTS")
        require(counts == (["CONTRACT_COUNTS", "16", "0", "0"] if mode == "normal" else
                           ["CONTRACT_COUNTS", "0", "1", "0"]), "completion totals")
        if mode == "normal":
            require(report["complete"] == 1 and report["streamed"] == 16 and len(events) == 16 and
                    status["child"] == 0 and status["records"] == 252, "normal streaming delivery")
            raw = [row.copy() for row in output if row[0] in
                   {"BEGIN", "END", "START", "STOP", "TARGET_EXIT", "RAW_ENTRY", "RAW_RETURN"}]
            for row in raw: row[0] = {"RAW_ENTRY": "ENTRY", "RAW_RETURN": "EVENT"}.get(row[0], row[0])
            with tempfile.TemporaryDirectory(prefix="procmon-native-decode-verify-") as temporary:
                path, stderr = Path(temporary) / "capture", Path(temporary) / "stderr"
                path.write_text((directory / f"run{number}" / "fixture.tsv").read_text() +
                                "\n".join("\t".join(row) for row in raw) + "\n")
                stderr.write_text("")
                result = subprocess.run([sys.executable, "-", str(path), str(stderr), "0", uid, gid], input=baseline, text=True)
                require(result.returncode == 0, "native decoder independent workload comparison")
        else:
            signal = 2 if mode == "sigint" else 15
            require(report["complete"] == report["streamed"] == 0 and status["signal"] == signal and
                    status["child"] == 137 and 0 < status["cancel_ns"] < 2000000000, "cancelled session policy")
            expected = (directory / "run1" / "fixture.tsv").read_text().strip().split("\t")
            key, entry = next(iter(entries.items()))
            require(expected[0] == "BLOCK_EXPECT" and entry[1:3] == expected[1:3] and
                    entry[3] == "read" and entry[5] == expected[3] and entry[6] == "1" and expected[4:6] == [uid, gid],
                    "blocked fixture identity")
        print(f"PASS: decoded-{mode} round {number}; raw clock, typed arguments, pairing and completeness")
