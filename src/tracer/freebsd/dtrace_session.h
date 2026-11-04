// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace procmon::freebsd
{

struct SessionOptions
{
    std::string bufferSize = "4m";
    std::string dynamicVariableSize = "4m";
    std::size_t maximumBatchBytes = 16 * 1024 * 1024;
    std::size_t maximumBatchProbes = 16384;
    std::size_t maximumBatchRecords = 131072;
    std::size_t maximumBatchNotices = 1024;
};

struct CapturedRecord
{
    std::uint32_t action = 0;
    std::uint64_t argument = 0;
    std::uint16_t alignment = 0;
    std::vector<std::uint8_t> bytes;
};

struct CapturedProbe
{
    std::string provider, module, function, name;
    int cpu = 0;
    std::vector<CapturedRecord> records;
};

enum class NoticeKind { RuntimeError, Drop };
struct SessionNotice
{
    NoticeKind kind = NoticeKind::RuntimeError;
    int detail = 0; // Native fault/drop kind, not an errno.
    std::uint64_t count = 0;
    std::string message;
};

enum class PollOutcome { Okay, Done, Error };
struct SessionBatch
{
    PollOutcome outcome = PollOutcome::Okay;
    std::vector<CapturedProbe> probes;
    std::vector<SessionNotice> notices;
};

struct SessionStatus
{
    bool attempted = false, opened = false, started = false, stopped = false;
    bool drained = false, closed = false, failed = false, discarded = false;
    std::uint64_t probes = 0, dataRecords = 0, zeroRecords = 0;
    std::uint64_t runtimeErrors = 0, drops = 0;
    std::string diagnostic;
};

// Synchronous, single-use session for FreeBSD amd64. Serialize all calls,
// including calls to other libdtrace components. No methods are signal-safe.
// Program text is trusted D source, with its filtering policy supplied by the
// caller. Start does not enforce PID/ABI filtering or manage target processes.
// Positional arguments become $1, $2, ...; the component supplies $0.
//
// Poll returns copied data, never library-owned pointers. Text/payload budgets
// and cardinality bounds limit each batch; allocation overhead is additional.
// Runtime faults/drops are observable notices/counters, not proof of complete
// capture. Fatal API/copy failures set failed and return an error outcome.
//
// Finish explicitly with Stop, Poll until Done, then Close. Close/destruction
// stop/close resources but cannot deliver pending data; closing an undrained
// started session sets discarded. Start failure closes the handle immediately.
// C++ allocation failures may propagate after closing. No modules are loaded,
// commands executed, targets killed, signal handlers installed, or formatting
// and syscall decoding performed here. This is not a persisted record ABI.
class DTraceSession
{
public:
    DTraceSession();
    ~DTraceSession();
    DTraceSession(const DTraceSession&) = delete;
    DTraceSession& operator=(const DTraceSession&) = delete;
    DTraceSession(DTraceSession&&) = delete;
    DTraceSession& operator=(DTraceSession&&) = delete;

    bool Start(const std::string& program, const std::vector<std::string>& arguments,
        const SessionOptions& options = {});
    SessionBatch Poll();
    bool Stop();
    void Close() noexcept;
    const SessionStatus& Status() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace procmon::freebsd
