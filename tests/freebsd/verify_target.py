#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent oracle, ABI, lifetime and guard evidence validation."""
import hashlib
import json
from pathlib import Path
import re
import sys
sys.dont_write_bytecode = True
import verify_diagnostic as base

check = base.require
PROFILES = ("all", "read", "write", "openat", "self", "exit7", "cancel", "term", "fault", "broken",
            "killed", "exec_native", "exec_compat", "compat", "zombie", "startup", "watch_error")


def target(summary, ready=None):
    value = summary["target"]
    check(set(value) == {"validated", "abi", "start_seconds", "start_microseconds", "exit_status", "stop_cause"}, "target schema/address privacy")
    check(value["validated"] is True and value["abi"] == "FreeBSD ELF64", "validated native ABI")
    check(type(value["start_seconds"]) is int and value["start_seconds"] >= 0 and
          type(value["start_microseconds"]) is int and 0 <= value["start_microseconds"] < 1000000, "start identity")
    if ready:
        for key in ("validated", "abi", "start_seconds", "start_microseconds"):
            check(ready["target"][key] == value[key], "stable target identity")
    return value


def drained(final):
    check(all(final["session"][key] is True for key in ("attempted", "opened", "started", "stopped", "drained", "closed")), "drained lifecycle")
    check(not final["session"]["failed"] and not final["session"]["discarded"] and final["decoder"]["finalized"], "resource quality")


def rejected(final, message):
    check(final["type"] == "summary" and final["reason"] == "failure" and final["complete"] is False, "preflight failure")
    check(not final["target"]["validated"] and final["target"]["abi"] is None and
          final["target"]["start_seconds"] is None and final["target"]["start_microseconds"] is None and
          final["target"]["exit_status"] is None and final["target"]["stop_cause"] == "preflight", "rejected target metadata")
    check(final["session"]["attempted"] is False and final["session"]["opened"] is False and final["decoder"] is None, "reject before DTrace")
    check(message in final["diagnostic"], "specific rejection diagnostic")


def extended(directory, name):
    fields = (directory / f"{name}.supervisor").read_text().strip().split("\t")
    check(len(fields) == 7 and fields[:2] == ["RESULT", name], "supervisor result")
    pid, monitor, status, child_status, alive = map(int, fields[2:])
    check(child_status == (7 if name == "exit7" else 143 if name == "killed" else 0), "independent child status")
    check(status == (0 if name in {"exit7", "killed"} else 1), "driver status")
    rows = base.records(directory / f"{name}.jsonl")
    final = rows[-1]
    check(final["target_pid"] == pid and final["monitor_pid"] == monitor and final["type"] == "summary", "final identity")
    if name in {"compat", "zombie"}:
        check(len(rows) == 1, "no ready/data on rejection")
        rejected(final, "FreeBSD ELF64" if name == "compat" else "zombie or kernel")
        return 0
    drained(final)
    value = target(final, rows[0] if name != "startup" else None)
    if name == "startup":
        check(len(rows) == 1 and final["reason"] == "failure" and not final["complete"] and
              "during capture startup" in final["diagnostic"] and value["stop_cause"] == "exit" and value["exit_status"] == 0,
              "exit inside go must not publish ready/success")
        return 0
    check(rows[0]["type"] == "ready", "ready before stream")
    events = [row for row in rows if row["type"] == "event"]
    for event in events:
        check(event["pid"] == pid and event["tid"] > 0 and event["clock"] == "dtrace-session-ns", "scoped event")
        if event["raw_entry_ns"] is not None:
            check(event["raw_entry_ns"] - final["decoder"]["start_ns"] == event["timestamp_ns"] >= 0, "clock origin")
        if event["state"] == "completed":
            check(event["entry_present"] and event["return_present"] and
                  event["raw_entry_ns"] + event["duration_ns"] <= final["decoder"]["end_ns"], "completed clock/evidence")
        else:
            check(event["result"] is None and event["errno"] is None and event["duration_ns"] is None, "no fabricated unresolved return")
    for state in ("completed", "cancelled", "incomplete"):
        check(sum(event["state"] == state for event in events) == final["decoder"][state], "final count agreement")
    check(final["session"]["drops"] == final["session"]["runtime_errors"] == 0, "no unreported loss/fault")
    fixture = (directory / f"{name}.fixture").read_text()
    if name in {"exit7", "killed"}:
        check(final["complete"] and final["decoder"]["complete"] and final["reason"] == "completed" and
              value["stop_cause"] == "exit" and value["exit_status"] == (7 << 8 if name == "exit7" else 15), "exit status distinct from capture quality")
        if name == "exit7":
            check(f"FIXTURE\t{pid}\t6\t0" in fixture and len(events) >= 6, "nonzero-exit workload")
        else:
            block = next(line.split("\t") for line in fixture.splitlines() if line.startswith("BLOCK_EXPECT\t"))
            check(any(event["operation"] == "read" and event["descriptor"] == int(block[3]) and
                      event["result"] == -1 and event["errno"] == 4 for event in events), "actual EINTR before signalled exit")
    else:
        check(final["reason"] == "failure" and not final["complete"] and alive == 1 and value["exit_status"] is None, "policy failure, surviving target")
        check("BLOCK_RESULT\t" in fixture and any(line.endswith("\t1\t0") for line in fixture.splitlines() if line.startswith("BLOCK_RESULT\t")), "read after capture closure")
        if name.startswith("exec_"):
            check(value["stop_cause"] == "exec" and ("exec ended" in final["diagnostic"] or
                  (final["decoder"]["incomplete"] > 0 and "unresolved" in final["diagnostic"])), "exec failure with retained controller diagnostic")
            check(f"AFTER_EXEC\t{pid}\t{4 if name == 'exec_compat' else 8}" in fixture, "real executable ABI transition")
            if name == "exec_compat":
                check(not events, "compat calls excluded after exec")
        else:
            check(value["stop_cause"] == "watch_error" and "poll exit/exec watch" in final["diagnostic"], "watch error is failure")
    return len(events)


def verify(directory, repository):
    base.support(directory)
    for unit, count, label in (("watch", 50, "target-watch"), ("generation", 8, "identity generation"),
                               ("program", 19, "native program"), ("decoder", 64, ""), ("controller", 40, "")):
        text = (directory / f"{unit}.stdout").read_text()
        check(f"{count}" in text and text.startswith("PASS:") and (not label or label in text), "unit checks")
        check((directory / f"{unit}.exit").read_text().strip() == "0" and not (directory / f"{unit}.stderr").read_bytes(), "unit exit")
    for name in ("pilot", "runtime", "fixture", "fixture32", "watch", "guard", "hooked", "generation", "program", "decoder", "controller", "support"):
        check((directory / f"{name}-build.exit").read_text().strip() == "0" and
              not (directory / f"{name}-build.stdout").read_bytes() and not (directory / f"{name}-build.stderr").read_bytes(), "warning-free build")
    hashes = {}
    for line in (directory / "inputs.sha256").read_text().splitlines():
        match = re.fullmatch(r"SHA256 \((.+)\) = ([0-9a-f]{64})", line); check(match, "input hash syntax")
        path, digest = match.groups(); hashes[path] = digest
        check(hashlib.sha256((repository / path).read_bytes()).hexdigest() == digest, f"tested source differs: {path}")
    check(len(hashes) == 24, "24 native source/recipe/runner identities")
    abi = (directory / "fixture-abis.txt").read_text()
    check("ELF 64-bit" in abi and "ELF 32-bit" in abi and "FreeBSD" in abi, "native/compat binaries")
    totals = {}
    for name in PROFILES:
        check((directory / f"{name}.exit").read_text().strip() == "0" and not (directory / f"{name}.supervisor-error").read_bytes(), "runtime harness")
        if name in {"all", "read", "write", "openat", "self", "cancel", "term", "fault", "broken"}:
            totals[name] = base.profile(directory, name)
            if name != "broken":
                rows = base.records(directory / f"{name}.jsonl"); value = target(rows[-1], rows[0])
                cause = "duration" if name == "self" else "signal" if name in {"cancel", "term"} else "capture_failure" if name == "fault" else "exit"
                check(value["stop_cause"] == cause and value["exit_status"] == (0 if name in {"all", "read", "write", "openat"} else None), "stop cause and lifetime status")
        else:
            totals[name] = extended(directory, name)
    for name in ("matching", "address", "seconds", "microseconds"):
        prefix = f"guard-{name}"
        check((directory / f"{prefix}.exit").read_text().strip() == "0" and not (directory / f"{prefix}.stderr").read_bytes(), "guard harness")
        rows = base.records(directory / f"{prefix}.jsonl"); final = rows[-1]; drained(final)
        check(final["complete"] and final["decoder"]["complete"], "guard transport complete")
        events = rows[:-1]
        check(all(row["type"] == "event" and row["pid"] == final["target_pid"] for row in events), "guard event scope")
        if name == "matching":
            fixture = (directory / f"{prefix}-files" / f"{prefix}.fixture").read_text()
            oracle = [line.split("\t") for line in fixture.splitlines() if line.startswith("EXPECT\t")]
            check(len(oracle) == 6, "guard independent oracle")
            for _, pid, tid, operation, _, fd, third, result, error, _ in oracle:
                check(any(event["pid"] == int(pid) and event["tid"] == int(tid) and event["operation"] == operation and
                          event["descriptor"] == int(fd) and event["third"] == int(third) and event["result"] == int(result) and
                          event["errno"] == int(error) for event in events), "matching identity captures actual calls")
        else:
            check(not events and final["decoder"]["completed"] == 0, "mismatched identity excluded")
    for pid, message in ((2147483647, "No such process"), (2, "zombie or kernel")):
        final, = base.records(directory / f"reject-{pid}.jsonl"); rejected(final, message)
        check((directory / f"reject-{pid}.exit").read_text().strip() == "1", "preflight exit")
    check((directory / "cli.stdout").read_text() == "CLI_CASES\t13\n" and not (directory / "cli.stderr").read_bytes(), "CLI cases")
    denial, = base.records(directory / "cli-denied.stdout")
    check(denial["reason"] == "failure" and denial["session"]["attempted"] and not denial["session"]["opened"] and
          "privileges" in denial["diagnostic"], "ordinary-user tracing denial")
    check((directory / "make-up-to-date.exit").read_text().strip() == "0" and
          (directory / "process-check.exit").read_text().strip() == "1" and not (directory / "processes.txt").read_bytes(), "build current, no leftover test processes")
    return totals


def negative_controls(directory):
    import shutil
    import tempfile
    mutations = (("exec_native", "abi", "FreeBSD ELF32"), ("exec_native", "start_seconds", -1),
                 ("killed", "exit_status", 0), ("exec_native", "stop_cause", "exit"),
                 ("watch_error", "stop_cause", "duration"))
    for name, key, value in mutations:
        with tempfile.TemporaryDirectory(prefix="procmon-target-mutant-") as temporary:
            altered = Path(temporary)
            for path in directory.iterdir():
                if path.is_file(): shutil.copyfile(path, altered / path.name)
            path = altered / f"{name}.jsonl"
            rows = [base.load(line) for line in path.read_text().splitlines()]
            rows[-1]["target"][key] = value
            path.write_text("".join(json.dumps(row, ensure_ascii=True) + "\n" for row in rows))
            try: extended(altered, name)
            except (AssertionError, KeyError, TypeError): continue
            raise AssertionError(f"accepted corrupted target {key}")
    return len(mutations)


if __name__ == "__main__":
    check(len(sys.argv) == 3, "usage: verify_target.py RESULTS REPOSITORY")
    print("PASS:", verify(Path(sys.argv[1]), Path(sys.argv[2])))
    print("REJECTED prior corruption controls:", base.negative_controls(Path(sys.argv[1])))
    print("REJECTED target corruption controls:", negative_controls(Path(sys.argv[1])))
