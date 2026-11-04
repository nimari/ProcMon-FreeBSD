// SPDX-License-Identifier: MIT
#pragma once

#include "dtrace_session.h"

#include <optional>

namespace procmon::freebsd
{

enum class NativeOperation { OpenAt, Read, Write };
enum class NativeEventState { Completed, Cancelled, Incomplete };
enum class NativeClock { DTraceSessionNs = 1 };

struct CapturedPath
{
    std::string text;
    bool atCaptureLimit = false; // 64 bytes; does not prove actual truncation.
};

struct NativeArguments
{
    std::int64_t descriptor = 0; // fd or dirfd, sign extended from native int.
    std::uint64_t third = 0; // count for read/write, raw flags for openat.
    std::optional<CapturedPath> path;
    // This initial schema does not capture buffer pointers, contents or mode.
};

struct NativeReturnDiagnostic
{
    std::int64_t result = 0;
    std::uint64_t errnoBits = 0, durationNs = 0;
};

struct NativeEvent
{
    unsigned int version = 1;
    NativeClock clock = NativeClock::DTraceSessionNs;
    std::uint64_t pid = 0, tid = 0;
    std::uint64_t correlationStartNs = 0; // Raw key, not evidence of an observed entry.
    NativeOperation operation = NativeOperation::Read;
    NativeEventState state = NativeEventState::Incomplete;
    bool entryPresent = false, returnPresent = false;
    std::optional<std::uint64_t> rawEntryNs, timestampNs, durationNs;
    std::optional<std::int64_t> result;
    std::optional<std::uint32_t> error;
    std::optional<int> entryCpu, returnCpu;
    NativeArguments arguments;
    std::optional<NativeReturnDiagnostic> returned;
};

enum class DecodeIssueKind { UnsupportedSchema, MalformedRecord, DuplicateRecord,
    Capacity, Clock, Protocol, Transport };
struct DecodeIssue
{
    DecodeIssueKind kind = DecodeIssueKind::MalformedRecord;
    std::string message;
};

struct DecoderReport
{
    bool finalized = false, complete = false, cancellationRequested = false;
    NativeClock clock = NativeClock::DTraceSessionNs;
    std::optional<std::uint64_t> startNs, endNs;
    std::uint64_t completed = 0, cancelled = 0, incomplete = 0;
    std::uint64_t runtimeErrors = 0, drops = 0;
    std::optional<DecodeIssue> issue;
};

struct DecodedBatch
{
    std::vector<NativeEvent> events;
    std::optional<DecodeIssue> issue;
};

// Internal v1 layout from session_records.d or BuildNativeProgram, not a general
// D decoder or persisted ABI. Streams completed pairs once BEGIN is known; END
// may arrive before other CPUs' data. Check the final Report before declaring
// the capture complete: already-emitted events cannot retract later loss/errors.
//
// Pair key: PID/TID/operation/raw entry timestamp. Return-first delivery works.
// Pending and recent completed-key history are bounded independently; duplicate
// detection after retirement covers only the retained recent keys, not arbitrary
// replay. This consumes the session's single-pass stream, not trace replay.
//
// Finish only after Stop/Poll-to-Done/Close. An unresolved entry is cancelled
// only with explicit cancellation evidence; orphans never invent entry/time.
// Ordinary nonnegative 32-bit errno lanes may complete; this is a representable
// lane check, not validation that every such number is an assigned FreeBSD errno.
// Invalid/sentinel return bits remain diagnostic. C++ allocation failures throw;
// discard that decoder instance. Caller misuse after Finish throws logic_error.
class NativeEventDecoder
{
public:
    explicit NativeEventDecoder(std::uint64_t targetPid, std::size_t maximumPending = 4096,
        std::size_t recentCompletedKeys = 4096);
    ~NativeEventDecoder();
    NativeEventDecoder(const NativeEventDecoder&) = delete;
    NativeEventDecoder& operator=(const NativeEventDecoder&) = delete;
    NativeEventDecoder(NativeEventDecoder&&) = delete;
    NativeEventDecoder& operator=(NativeEventDecoder&&) = delete;

    DecodedBatch Consume(const SessionBatch& batch);
    DecodedBatch Finish(const SessionStatus& session, bool cancellationRequested);
    const DecoderReport& Report() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace procmon::freebsd
