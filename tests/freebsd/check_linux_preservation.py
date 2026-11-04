#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare shared source as seen with __FreeBSD__ undefined to the original upstream base."""
from pathlib import Path
import re
import subprocess

BASE = "a40cf056351d19830a96d2d22beed96a18f7707c"
PATHS = ("src/common/telemetry.h", "src/storage/storage_proxy.h", "src/configuration/procmon_configuration.h",
         "src/display/screen.h", "src/display/screen.cpp", "src/display/column.cpp", "src/display/column.h")


def linux_view(text):
    output, gates = [], []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped in {"#ifdef __FreeBSD__", "#ifndef __FreeBSD__"}:
            gates.append(stripped == "#ifndef __FreeBSD__")
            continue
        if re.match(r"#\s*(if|ifdef|ifndef)\b", stripped):
            if False not in gates: output.append(line)
            gates.append(None)
            continue
        if stripped == "#else" and gates and gates[-1] is not None:
            gates[-1] = not gates[-1]
            continue
        if stripped.startswith("#endif") and gates:
            gate = gates.pop()
            if gate is not None: continue
        if False not in gates: output.append(line)
    return [line.rstrip() for line in output if line.strip()]


root = Path(__file__).resolve().parents[2]
for path in PATHS:
    previous = subprocess.check_output(["git", "show", f"{BASE}:{path}"], cwd=root, text=True)
    assert linux_view(previous) == linux_view((root / path).read_text()), f"Linux source view changed: {path}"
previous = subprocess.check_output(["git", "show", f"{BASE}:CMakeLists.txt"], cwd=root, text=True)
current = (root / "CMakeLists.txt").read_text()
branch = 'if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")\n    include(cmake/FreeBSD.cmake)\n    return()\nendif()\n'
assert current.count(branch) == 1
assert [line.rstrip() for line in current.replace(branch, "").splitlines() if line.strip()] == [line.rstrip() for line in previous.splitlines() if line.strip()]
print("PASS: Linux views of seven shared source/header files and default CMake body are unchanged")
