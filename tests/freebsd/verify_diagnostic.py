#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent JSON/oracle/lifecycle checks for the standalone diagnostic pilot."""
import collections
import hashlib
import json
from pathlib import Path
import re
import sys


def require(value, message):
    if not value:
        raise AssertionError(message)


def unique_object(items):
    require(len(dict(items)) == len(items), "duplicate JSON key")
    return dict(items)


def load(text):
    require(text.isascii(), "wire output must be ASCII")
    return json.loads(text, object_pairs_hook=unique_object)


def records(path):
    lines = path.read_text().splitlines()
    require(lines and path.read_bytes().endswith(b"\n"), f"truncated output: {path.name}")
    result = [load(line) for line in lines]
    for row in result:
        require(row["schema"] == "procmon-freebsd-diagnostic" and row["version"] == 1, "schema")
        require(row["type"] in {"ready", "event", "notice", "summary"}, "record type")
    return result


def support(directory):
    lines = (directory / "support.stdout").read_text().splitlines()
    require(lines[0] == "CHECKS\t34", "support checks")
    all_bytes = bytes(range(256))
    require(load(lines[1]).encode("latin1") == all_bytes, "all-byte JSON round trip")
    incomplete, completed, cancelled, summary, ready, drop, fault = map(load, lines[2:])
    require(incomplete["path"]["bytes"].encode("latin1") == all_bytes, "path encoding")
    require(incomplete["descriptor"] == -100 and incomplete["third"] == 2**64 - 1, "signed/unsigned arguments")
    require(incomplete["return_diagnostic"] == {"result": -1, "errno_bits": 2**64 - 1, "duration_ns": 99}, "diagnostic lanes")
    require(incomplete["state"] == "incomplete" and incomplete["timestamp_ns"] is None, "missing time")
    require(completed["state"] == "completed" and completed["result"] == -2 and completed["errno"] == 0, "negative success")
    require(completed["entry_cpu"] == 0 and completed["return_cpu"] == 1 and completed["path"] is None, "CPU/path options")
    require(cancelled["state"] == "cancelled" and not cancelled["return_present"] and
            all(cancelled[key] is None for key in ("duration_ns", "result", "errno", "return_cpu")), "cancelled nulls")
    require(summary["decoder"]["issue"]["message"].encode("latin1") == all_bytes, "diagnostic encoding")
    require(summary["reason"] == "failure" and not summary["complete"], "summary quality")
    require(ready["events"] == ["write", "read"] and ready["duration_ms"] == 86400000, "ready options")
    require(drop["kind"] == "drop" and drop["count"] == 7 and drop["message"].encode("latin1") == all_bytes, "drop notice")
    require(fault["kind"] == "runtime_error" and fault["count"] == 1, "fault notice")
    require(not (directory / "support.stderr").read_bytes(), "support stderr")


def profile(directory, name):
    require((directory / f"{name}.exit").read_text().strip() == "0", f"{name}: harness exit")
    require(not (directory / f"{name}.supervisor-error").read_bytes(), "harness error")
    fields = (directory / f"{name}.supervisor").read_text().strip().split("\t")
    require(len(fields) == 7 and fields[:2] == ["RESULT", name], "supervisor record")
    pid, monitor, status, target_status, alive = map(int, fields[2:])
    require(pid > 0 and monitor > 0 and target_status == 0, "fixture status")
    expected_status = {"cancel": 130, "term": 143, "fault": 1, "broken": 1}.get(name, 0)
    require(status == expected_status, "driver exit status")
    if name == "broken":
        require(alive == 1 and "capture output failed" in (directory / "broken.stderr").read_text(), "output failure cleanup")
        fixture = (directory / "broken.fixture").read_text().splitlines()
        require(any(line.startswith("BLOCK_RESULT\t") and line.endswith("\t1\t0") for line in fixture), "surviving read")
        return 0
    rows = records(directory / f"{name}.jsonl")
    require(rows[0]["type"] == "ready" and rows[-1]["type"] == "summary", "boundary order")
    require(sum(row["type"] == "ready" for row in rows) == 1 and
            sum(row["type"] == "summary" for row in rows) == 1, "boundary uniqueness")
    ready, final = rows[0], rows[-1]
    selected = [name] if name in {"read", "write", "openat"} else ["openat", "read", "write"]
    require(ready["events"] == selected and ready["platform"] == "freebsd-amd64" and
            ready["string_encoding"] == "byte-codepoints" and ready["clock"] == "dtrace-session-ns", "ready schema")
    for boundary in (ready, final):
        require(boundary["target_pid"] == pid and boundary["monitor_pid"] == monitor, "PID identity")
    session, decoder = final["session"], final["decoder"]
    require(all(session[key] is True for key in ("attempted", "opened", "started", "stopped", "drained", "closed")), "session lifecycle")
    require(not session["failed"] and not session["discarded"] and decoder["finalized"], "drained quality")
    require(decoder["issue"] is None and session["drops"] == decoder["drops"] == 0, "decoder/drop status")
    require(final["stop_requested"] is True, "stop intent")
    events = [row for row in rows if row["type"] == "event"]
    notices = [row for row in rows if row["type"] == "notice"]
    counts = collections.Counter(event["state"] for event in events)
    for state in ("completed", "cancelled", "incomplete"):
        require(counts[state] == decoder[state], "stream/final count agreement")
    keys = set()
    for event in events:
        require(event["pid"] == pid and pid != monitor and event["tid"] > 0, "scope/self exclusion")
        require(event["operation"] in selected and event["clock"] == "dtrace-session-ns", "operation/clock")
        key = event["tid"], event["operation"], event["correlation_start_ns"]
        require(key not in keys, "duplicate event"); keys.add(key)
        require(event["entry_present"] and event["raw_entry_ns"] == event["correlation_start_ns"], "entry evidence")
        require(event["raw_entry_ns"] - decoder["start_ns"] == event["timestamp_ns"] >= 0, "timestamp origin")
        require(event["raw_entry_ns"] <= decoder["end_ns"], "END bound")
        if event["state"] == "completed":
            require(event["return_present"] and type(event["result"]) is int and type(event["errno"]) is int, "return evidence")
            require(event["duration_ns"] >= 0 and event["raw_entry_ns"] + event["duration_ns"] <= decoder["end_ns"], "duration bounds")
            require(event["return_diagnostic"] == {"result": event["result"], "errno_bits": event["errno"],
                                                  "duration_ns": event["duration_ns"]}, "raw return evidence")
        else:
            require(not event["return_present"] and all(event[key] is None for key in
                    ("duration_ns", "result", "errno", "return_cpu", "return_diagnostic")), "unresolved return nulls")
    if name in {"cancel", "term", "fault"}:
        require(alive == 1, "non-owning cancellation/failure")
        fixture = (directory / f"{name}.fixture").read_text().splitlines()
        blocked = next(line.split("\t") for line in fixture if line.startswith("BLOCK_EXPECT\t"))
        require(any(line == f"BLOCK_RESULT\t{pid}\t{blocked[2]}\t1\t0" for line in fixture), "target read after closure")
        unresolved = [event for event in events if event["operation"] == "read" and
                      event["descriptor"] == int(blocked[3]) and event["third"] == 1 and event["state"] != "completed"]
        require(len(unresolved) == 1, "blocked read retained in final batch")
        require(not final["complete"] and not decoder["complete"], "no false complete")
        if name == "fault":
            require(final["reason"] == "failure" and final["signal"] == 0 and not final["cancellation_requested"], "fault reason")
            require(unresolved[0]["state"] == "incomplete" and final["diagnostic"], "fault unresolved state")
            require(session["runtime_errors"] == decoder["runtime_errors"] == sum(row["count"] for row in notices) > 0 and
                    all(row["kind"] == "runtime_error" for row in notices), "real fault accounting")
        else:
            require(final["reason"] == "cancelled" and final["signal"] == (2 if name == "cancel" else 15) and
                    final["cancellation_requested"] and unresolved[0]["state"] == "cancelled", "signal cancellation")
    else:
        require(final["complete"] and decoder["complete"] and final["reason"] == "completed" and
                final["signal"] == 0 and not final["cancellation_requested"], "timed complete")
        require(not final["diagnostic"] and not notices and session["runtime_errors"] == 0, "clean complete")
        require(not (directory / f"{name}.stderr").read_bytes(), "unexpected stderr")
        if name == "self":
            require(pid == monitor and not events, "self capture")
        else:
            expected = [line.split("\t") for line in (directory / f"{name}.fixture").read_text().splitlines() if line.startswith("EXPECT\t")]
            require(len(expected) == 6 and f"FIXTURE\t{pid}\t6\t0" in (directory / f"{name}.fixture").read_text(), "six-call independent oracle")
            for _, p, tid, operation, _, fd, third, result, error, path in expected:
                if operation not in selected:
                    continue
                matches = [event for event in events if event["operation"] == operation and event["tid"] == int(tid) and
                           event["pid"] == int(p) and event["descriptor"] == int(fd) and event["third"] == int(third) and
                           event["result"] == int(result) and event["errno"] == int(error)]
                require(len(matches) == 1, "oracle event unique match")
                captured = matches[0]["path"]
                if operation == "openat":
                    require(captured == {"bytes": path[:64], "at_capture_limit": len(path) >= 64}, "bounded path")
                else:
                    require(captured is None, "read/write path absent")
    return len(events)


def verify(directory, repository):
    support(directory)
    for prefix in ("build", "runtime-build", "support-build", "unmarked-build", "controlled-build"):
        require(not (directory / f"{prefix}.stdout").read_bytes() and not (directory / f"{prefix}.stderr").read_bytes(), "warning-free build")
    require((directory / "make-up-to-date.exit").read_text().strip() == "0", "incremental make")
    require((directory / "make-repeat.exit").read_text().strip() == "0" and
            not (directory / "make-repeat.stdout").read_bytes() and not (directory / "make-repeat.stderr").read_bytes() and
            (directory / "binary-before.txt").read_bytes() == (directory / "binary-after.txt").read_bytes(), "no rebuild needed")
    require((directory / "process-check.exit").read_text().strip() == "1" and
            not (directory / "processes.txt").read_bytes(), "no remaining test processes")
    hashes = {}
    for line in (directory / "inputs.sha256").read_text().splitlines():
        match = re.fullmatch(r"SHA256 \((.+)\) = ([0-9a-f]{64})", line)
        require(match, "source hash syntax")
        path, digest = match.groups(); hashes[path] = digest
        require(hashlib.sha256((repository / path).read_bytes()).hexdigest() == digest, f"tested source differs: {path}")
    require(len(hashes) == 16, "native input hash count")
    require((directory / "cli.stdout").read_text() == "CLI_CASES\t13\n" and not (directory / "cli.stderr").read_bytes(), "CLI script")
    for name in ("help", "missing", "zero", "negative", "overflow", "garbage", "unknown", "empty", "trailing", "duplicate", "value", "duration", "denied"):
        status = int((directory / f"cli-{name}.exit").read_text())
        require(status == (0 if name == "help" else 1 if name == "denied" else 2), "CLI exit")
        stdout = (directory / f"cli-{name}.stdout").read_text()
        stderr = (directory / f"cli-{name}.stderr").read_text()
        if name == "help":
            require("diagnostic pilot" in stdout and "PID reuse" in stdout and not stderr, "help")
        elif name == "denied":
            final, = records(directory / "cli-denied.stdout")
            require(final["type"] == "summary" and final["reason"] == "failure" and not final["complete"] and
                    final["session"]["attempted"] and not final["session"]["opened"] and final["session"]["closed"] and
                    final["session"]["failed"] and final["diagnostic"] and stderr, "privilege denial")
        else:
            require(not stdout and stderr, "usage must precede tracing")
    totals = {name: profile(directory, name) for name in ("all", "read", "write", "openat", "self", "cancel", "term", "fault", "broken")}
    return totals


def negative_controls(directory):
    """Ensure plausible corrupt output cannot pass the independent checks."""
    import shutil
    import tempfile
    mutations = [
        ("target", "all", "event", "pid", 1),
        ("operation", "read", "event", "operation", "write"),
        ("timestamp", "all", "event", "timestamp_ns", -1),
        ("return", "all", "event", "result", 999999),
        ("quality", "cancel", "summary", "complete", True),
        ("cancel", "cancel", "event", "result", 0),
        ("reason", "fault", "summary", "reason", "completed"),
        ("monitor", "self", "ready", "monitor_pid", 1),
    ]
    for label, name, kind, key, value in mutations:
        with tempfile.TemporaryDirectory(prefix="procmon-diagnostic-mutant-") as temporary:
            altered = Path(temporary)
            for path in directory.iterdir():
                if path.is_file():
                    shutil.copyfile(path, altered / path.name)
            path = altered / f"{name}.jsonl"
            rows = [load(line) for line in path.read_text().splitlines()]
            row = next(row for row in rows if row.get("state") == "cancelled") if label == "cancel" else next(
                row for row in rows if row["type"] == kind)
            row[key] = value
            path.write_text("".join(json.dumps(row, ensure_ascii=True) + "\n" for row in rows))
            try:
                profile(altered, name)
            except (AssertionError, KeyError, TypeError):
                continue
            raise AssertionError(f"accepted corrupted {label}")
    return len(mutations)


if __name__ == "__main__":
    require(len(sys.argv) == 3, "usage: verify_diagnostic.py RESULTS REPOSITORY")
    print("PASS:", verify(Path(sys.argv[1]), Path(sys.argv[2])))
    print("REJECTED altered-output controls:", negative_controls(Path(sys.argv[1])))
