#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify the reusable session against the established independent fixtures."""

from pathlib import Path
import re
import subprocess
import sys
import tempfile


def require(condition, message):
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def one(rows, tag):
    found = [row for row in rows if row[0] == tag]
    require(len(found) == 1, f"expected one {tag}")
    return found[0]


if len(sys.argv) != 4:
    raise SystemExit("usage: verify_dtrace_session.py results-directory uid gid")
root = Path(sys.argv[1])
uid, gid = sys.argv[2:4]
readme = Path(__file__).with_name("README.md").read_text()
baseline = readme.split("EXPECTED_GID <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
for build in ("component", "test", "fixture", "signal"):
    require(not (root / f"{build}-build.stdout").read_text() and
            not (root / f"{build}-build.stderr").read_text(), f"{build}: final build diagnostics")
for mode in ("normal", "fault", "drop", "startup", "limit", "abandon", "sigint", "sigterm", "denied"):
    directory = root / mode
    require(int((directory / "exit-status").read_text()) == 0, f"{mode}: harness assertions failed")
    text = (directory / "records.tsv").read_text()
    diagnostic = (directory / "stderr").read_text()
    require("SESSION_TEST_FAILURE" not in diagnostic, f"{mode}: unexpected test failure")
    rows = [line.split("\t") for line in text.splitlines() if line]
    if mode == "denied":
        require(len(rows) == 1 and len(rows[0]) == 2 and rows[0][0] == "DENIED" and
                rows[0][1].startswith("open:") and not diagnostic, "denied: wrong failure stage")
        print("PASS: denied startup closes without a successful open")
        continue
    rounds, current = {}, None
    for row in rows:
        if row[0] == "ROUND":
            require(len(row) == 2 and int(row[1]) not in rounds, "duplicate/invalid round")
            current = int(row[1]); rounds[current] = []
        elif row[0] != "DESTRUCTOR_TEST":
            require(current is not None, "record outside round")
            rounds[current].append(row)
    require(rounds.keys() == ({1, 2} if mode == "normal" else {1}), f"{mode}: missing rounds")
    if mode == "normal":
        require(one(rows, "DESTRUCTOR_TEST") ==
                ["DESTRUCTOR_TEST", "opens=1", "closes=1", "stops=1", "passed=1"],
                "active destructor cleanup")
    else:
        require(not any(row[0] == "DESTRUCTOR_TEST" for row in rows), "unexpected destructor case")
    for number, output in rounds.items():
        status = one(output, "SESSION_STATUS")
        pairs = [field.split("=", 1) for field in status[1:]]
        require(all(len(pair) == 2 for pair in pairs), "status shape")
        values = dict(pairs)
        require(len(values) == len(pairs) and values.pop("mode") == mode, "status mode/duplicates")
        state = {key: int(value) for key, value in values.items()}
        keys = {"round", "pid", "opened", "started", "stopped", "drained", "closed", "failed",
                "discarded", "probes", "records", "zero", "errors", "drops", "reaped", "child",
                "blocked", "signal", "cancel_ns", "opens", "closes"}
        require(state.keys() == keys and all(value >= 0 for value in state.values()), "status fields")
        require(state["round"] == number and state["pid"] > 0 and state["opened"] ==
                state["closed"] == state["reaped"] == 1 and
                state["opens"] == state["closes"] == number, "handle/child cleanup")
        raw = [row for row in output if row[0] != "SESSION_STATUS"]
        pid = str(state["pid"])
        if mode in {"startup", "abandon", "limit"}:
            require(not raw and state["drained"] == 0 and state["probes"] ==
                    state["records"] == state["zero"] == state["errors"] == state["drops"] == 0,
                    f"{mode}: falsely completed data")
            require(state["started"] == state["stopped"] == (mode != "startup") and
                    state["discarded"] == (mode != "startup") and
                    state["failed"] == (mode != "abandon"), f"{mode}: state validity")
            if mode == "abandon":
                require(not diagnostic, "abandon: unexpected failure")
            else:
                require(diagnostic.startswith("SESSION_FAILURE\t" +
                    ("compile:" if mode == "startup" else "callback: batch byte limit exceeded")),
                    f"{mode}: wrong failure stage")
        else:
            require(state["started"] == state["stopped"] == state["drained"] == 1 and
                    state["failed"] == state["discarded"] == 0, f"{mode}: lifecycle incomplete")
            require(one(raw, "BEGIN") == ["BEGIN", pid] and one(raw, "END") == ["END"], "missing final data")
            if mode == "normal":
                require(not diagnostic and state["child"] == state["errors"] == state["drops"] == 0 and
                        (state["probes"], state["records"], state["zero"]) == (37, 250, 130), "normal counters")
                with tempfile.TemporaryDirectory(prefix="procmon-session-verify-") as temporary:
                    capture, stderr = Path(temporary) / "capture.tsv", Path(temporary) / "stderr"
                    capture.write_text((directory / f"run{number}" / "fixture.tsv").read_text() +
                                       "\n".join("\t".join(row) for row in raw) + "\n")
                    stderr.write_text("")
                    result = subprocess.run([sys.executable, "-", str(capture), str(stderr), "0", uid, gid],
                                            input=baseline, text=True)
                    require(result.returncode == 0, f"normal round {number}: independent workload mismatch")
            elif mode == "fault":
                require(state["errors"] > 0 and state["drops"] == 0 and
                        diagnostic.count("SESSION_ERROR\t") == state["errors"] and
                        "SESSION_FAILURE" not in diagnostic, "real runtime error not surfaced")
            elif mode == "drop":
                counts = [int(match[1]) for match in re.findall(r"^SESSION_DROP\t(\d+)\t(\d+)\t", diagnostic, re.M)]
                require(state["drops"] > 0 and sum(counts) == state["drops"] and
                        state["errors"] == state["child"] == 0 and "SESSION_FAILURE" not in diagnostic,
                        "real drops not surfaced")
            else:
                signal = 2 if mode == "sigint" else 15
                require(not diagnostic and state["errors"] == state["drops"] == 0 and
                        state["blocked"] == 1 and state["signal"] == signal and state["child"] == 137 and
                        0 < state["cancel_ns"] < 2000000000, "controlled signal cleanup")
                expected = (directory / "run1" / "fixture.tsv").read_text().strip().split("\t")
                blocked = one(raw, "BLOCKED")
                require(len(expected) == len(blocked) == 6 and expected[0] == "BLOCK_EXPECT" and
                        expected[1] == blocked[1] == pid and expected[2] == blocked[2] and
                        expected[3] == blocked[4] and expected[4:] == [uid, gid] and blocked[5] == "1",
                        "blocked fixture/PID/TID/identity mismatch")
                require(int(blocked[3]) >= int(one(raw, "START")[2]), "blocked read outside markers")
                returns = [row for row in raw if row[0] == "BLOCK_RETURN"]
                require(len(returns) <= 1, "duplicate cancelled return")
                if returns:
                    require(len(returns[0]) == 6 and returns[0][1:3] == blocked[1:3] and
                            int(returns[0][5]) == 2**64 - 1, "cancelled return diagnostics changed")
        if mode not in {"sigint", "sigterm"}:
            require(state["signal"] == state["cancel_ns"] == 0, "unexpected cancellation")
        print(f"PASS: {mode} round {number}; lifecycle, ownership and expected failure policy")
