#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check API counters/lifecycle and reuse the established workload verifier."""

from pathlib import Path
import subprocess
import sys
import tempfile


def require(condition, message):
    if not condition:
        raise SystemExit(f"FAIL: {message}")


if len(sys.argv) != 4:
    raise SystemExit("usage: verify_libdtrace.py results-directory uid gid")

root = Path(sys.argv[1])
uid, gid = sys.argv[2:4]
summaries = {}
for case in ("normal", "fault", "drop", "startup"):
    directory = root / case
    parts = (directory / "api-status.tsv").read_text().strip().split("\t")
    require(parts[0] == "API_STATUS", f"{case}: missing status")
    pairs = [part.split("=", 1) for part in parts[1:]]
    require(all(len(pair) == 2 for pair in pairs), f"{case}: malformed status")
    values = dict(pairs)
    wanted = {"pid", "mode", "probes", "records", "zero_records", "entries", "returns",
              "errors", "drops", "schema", "started", "stopped", "drained",
              "closed", "reaped", "child_status", "startup_error", "blocked",
              "signal_sent", "signal_seen", "cancel_elapsed_ns"}
    require(len(values) == len(pairs) and values.keys() == wanted,
            f"{case}: unexpected status fields")
    require(values["mode"] == ("normal" if case == "startup" else case),
            f"{case}: wrong mode")
    counters = {key: int(value) for key, value in values.items() if key != "mode"}
    require(all(value >= 0 for value in counters.values()), f"{case}: negative counter")
    require(counters["pid"] > 0 and counters["closed"] == counters["reaped"] == 1,
            f"{case}: handle/child not cleaned up")
    require(counters["schema"] == 0, f"{case}: unexpected record schema")
    require(all(counters[key] == 0 for key in
                ("blocked", "signal_sent", "signal_seen", "cancel_elapsed_ns")),
            f"{case}: unexpected cancellation state")
    exit_code = int((directory / "exit-status").read_text())
    diagnostic = (directory / "stderr").read_text()
    if case == "normal":
        require(exit_code == 0 and not diagnostic, "normal: status or diagnostics")
        require(counters["errors"] == counters["drops"] == counters["startup_error"] == 0,
                "normal: unexpected failure")
        require(counters["entries"] == counters["returns"] == 16,
                "normal: incomplete calls")
        require(counters["probes"] == 37 and counters["records"] == 250,
                "normal: incomplete probe/record callbacks")
        require(counters["zero_records"] > 0, "normal: assignment descriptors not exercised")
        require(counters["child_status"] == 0, "normal: fixture failed")
    elif case == "fault":
        require(exit_code != 0 and counters["errors"] > 0 and counters["drops"] == 0,
                "fault: missing real error callback")
        require("API_ERROR\t" in diagnostic, "fault: missing error diagnostic")
        require(all(line.startswith("API_ERROR\t") for line in diagnostic.splitlines()),
                "fault: unexpected diagnostic")
    elif case == "drop":
        require(exit_code != 0 and counters["drops"] > 0 and counters["errors"] == 0,
                "drop: missing real drop callback")
        require("API_DROP\t" in diagnostic, "drop: missing drop diagnostic")
        require(all(line.startswith("API_DROP\t") for line in diagnostic.splitlines()),
                "drop: unexpected diagnostic")
        require(counters["child_status"] == 0, "drop: fixture did not complete")
    else:
        require(exit_code != 0 and counters["startup_error"] == 1,
                "startup: compile failure not reported")
        require(counters["started"] == counters["stopped"] == counters["drained"] == 0,
                "startup: probes unexpectedly started")
        require(counters["entries"] == counters["returns"] == 0,
                "startup: unexpected syscall records")
        require("API_FAILURE\tcompile/enable/go\t" in diagnostic,
                "startup: wrong failure stage")
    if case != "startup":
        require(counters["started"] == counters["stopped"] == counters["drained"] == 1,
                f"{case}: tracing not stopped/drained")
        require(counters["startup_error"] == 0, f"{case}: startup failed")
    summaries[case] = counters

readme = Path(__file__).with_name("README.md").read_text()
baseline = readme.split("EXPECTED_GID <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
begin_rows = [row.split("\t") for row in (root / "normal" / "records.tsv")
              .read_text().splitlines() if row.startswith("BEGIN\t")]
require(len(begin_rows) == 1 and len(begin_rows[0]) == 2 and
        int(begin_rows[0][1]) == summaries["normal"]["pid"],
        "normal: status PID differs from captured PID")
with tempfile.TemporaryDirectory(prefix="procmon-api-verify-") as temporary:
    combined = Path(temporary) / "capture.tsv"
    combined.write_text((root / "normal" / "fixture.tsv").read_text() +
                        (root / "normal" / "records.tsv").read_text())
    command = [sys.executable, "-", str(combined), str(root / "normal" / "stderr"),
               "0", uid, gid]
    outcome = subprocess.run(command, input=baseline, text=True)
    require(outcome.returncode == 0, "normal: workload comparison failed")

print("PASS: libdtrace typed records, real error/drop callbacks, compile failure, stop/drain/close/reap")
for case, values in summaries.items():
    print(f"{case}: probes={values['probes']} records={values['records']} "
          f"errors={values['errors']} drops={values['drops']} "
          f"child_status={values['child_status']}")
