// SPDX-License-Identifier: MIT
#pragma once

#include "native_program.h"

namespace procmon::freebsd
{

enum class CapturePhase { Ready, Running, Stopping, Finished, Closed };
enum class CaptureEndReason { None, Completed, Cancelled, Failure, Abandoned };

struct CaptureConfiguration
{
    std::uint64_t targetPid = 0;
    std::vector<NativeOperation> operations;
    SessionOptions transport;
    std::size_t maximumPending = 4096, recentCompletedKeys = 4096;
    std::optional<NativeTargetIdentity> identity = std::nullopt;
};

struct CaptureUpdate
{
    std::vector<NativeEvent> events;
    std::vector<SessionNotice> notices;
    bool finished = false;
};

struct CaptureReport
{
    CapturePhase phase = CapturePhase::Ready;
    CaptureEndReason reason = CaptureEndReason::None;
    std::uint64_t targetPid = 0, monitorPid = 0;
    bool stopRequested = false, cancellationRequested = false, complete = false;
    SessionStatus session;
    std::optional<DecoderReport> decoder;
    std::string diagnostic;
};

// Synchronous, single-use native FreeBSD/amd64 capture controller. Supplies its
// actual getpid() for monitor exclusion and accepts only the generated v1 schema.
// It never creates/signals/kills targets, installs signal handlers, loads modules
// or supervises target lifetime/PID reuse. Callers own those policies separately.
// Serialize calls, including calls to other libdtrace components; do not fork an
// active controller or call methods in signal handlers.
//
// RequestStop accepts Completed or Cancelled and records intent. Poll performs
// stop/drain/close/final decoding. Continue Poll until finished; that update may
// contain the final events/notices. Runtime fault/drop/decode failure requests
// failure stop automatically. Fatal transport failure closes immediately.
// Check the final Report: streamed completed observations do not imply a complete
// capture. Completed stop with unresolved entries fails; explicit cancellation
// gives unresolved observed entries cancelled status without ordinary results.
//
// Close/destruction abandon an unfinished capture and cannot deliver its pending
// events. Close and terminal Poll are idempotent. Invalid configuration returns
// false with a terminal failure report; lifecycle misuse throws logic_error.
// Allocation exceptions from Start/Poll close resources before propagating.
// Report returns an owned copy and may throw without changing capture state;
// close/discard the instance if allocation fails.
class NativeCapture
{
public:
    NativeCapture();
    ~NativeCapture();
    NativeCapture(const NativeCapture&) = delete;
    NativeCapture& operator=(const NativeCapture&) = delete;
    NativeCapture(NativeCapture&&) = delete;
    NativeCapture& operator=(NativeCapture&&) = delete;

    bool Start(const CaptureConfiguration& configuration);
    void RequestStop(CaptureEndReason reason);
    CaptureUpdate Poll();
    void Close() noexcept;
    CaptureReport Report() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace procmon::freebsd
