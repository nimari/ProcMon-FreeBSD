// SPDX-License-Identifier: MIT
#pragma once

#include "native_event_decoder.h"

namespace procmon::freebsd
{

// Optional FreeBSD/amd64 identity guard. Values come from a validated native
// snapshot; start is the kernel's boot-relative p_stats->p_start, not wall time.
// Keep the kernel address private; it is not part of diagnostic output.
struct NativeTargetIdentity
{
    std::uint64_t processAddress = 0, startSeconds = 0, startMicroseconds = 0;
};

struct NativeProgramRequest
{
    std::uint64_t targetPid = 0;
    std::uint64_t monitorPid = 0;
    std::vector<NativeOperation> operations;
    std::optional<NativeTargetIdentity> identity = std::nullopt;
};

struct NativeProgram
{
    unsigned int schemaVersion = 1;
    std::uint64_t targetPid = 0, excludedPid = 0;
    std::vector<NativeOperation> operations; // Canonical order, duplicates removed.
    std::string source;
};

// Pure generation, with no tracing/process side effects. Invalid/zero/out-of-range
// native PIDs, empty filters and unsupported enum values throw invalid_argument.
// The caller must supply the actual monitor PID; this function does not discover
// identity or process lifetime. Selecting that same PID is allowed and yields an
// intentionally empty syscall capture because self-exclusion still applies.
// An optional identity additionally guards every entry/return against process
// address/start-time reuse and non-native ELF64 ABI. It requires kernel CTF.
//
// Emits the reviewed v1 native decoder layout with optional fixture controls
// omitted. Capture begins at go, without getpgid/fixture-marker gating. Only
// openat/read/write are supported, with the existing limited argument coverage.
// Returns without an observed entry are omitted (e.g. calls already in flight at
// attachment). Fault/drop notices remain necessary to assess capture quality.
// Uses syscall:freebsd only; it does not follow child PIDs, load modules, enable
// tracing, manage processes, or establish restart/nested-syscall semantics.
NativeProgram BuildNativeProgram(const NativeProgramRequest& request);

} // namespace procmon::freebsd
