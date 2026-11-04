// SPDX-License-Identifier: MIT
#pragma once
#include "platform.h"
#include "../dtrace_session.h"
#include "../native_program.h"
#include <map>

namespace procmon::freebsd::app
{
struct TargetBinding { std::uint64_t pid; NativeTargetIdentity identity; };
struct CaptureOptions
{
    std::vector<SyscallSchema> schemas;
    std::vector<TargetBinding> targets; // Empty selects native user processes.
    bool strings = true, buffers = true, stacks = true;
    bool allSyscalls = false;
};
struct CapturedEvent
{
    EventData data;
    std::uint64_t birthSeconds = 0, birthMicroseconds = 0, imageAddress = 0;
};
struct CaptureQuality
{
    std::optional<std::uint64_t> start, end;
    std::uint64_t runtimeErrors = 0, drops = 0, unresolved = 0, missingExtras = 0;
    bool done = false, closed = false;
};
std::vector<SyscallSchema> NativeSchemas();
std::string ApplicationProgram(const CaptureOptions& options, std::uint64_t monitorPid);
class ApplicationCapture
{
public:
    explicit ApplicationCapture(CaptureOptions options, std::optional<std::uint64_t> origin = std::nullopt);
    ~ApplicationCapture();
    void Start();
    std::vector<CapturedEvent> Poll();
    void Stop(bool cancellation);
    const CaptureQuality& Quality() const { return quality; }
private:
    struct Pending
    {
        CapturedEvent event;
        bool entry = false, returned = false;
        std::uint64_t rawDuration = 0, rawResult = 0, rawErrno = 0;
        std::map<unsigned, std::string> extras;
    };
    using Key = std::tuple<std::uint64_t, std::uint64_t, std::string, std::uint64_t>;
    CaptureOptions options;
    std::map<std::string, SyscallSchema> schemas;
    DTraceSession session;
    std::map<Key, Pending> pending;
    CaptureQuality quality;
    std::optional<std::uint64_t> origin;
    bool stopping = false, cancellation = false;
    std::uint64_t maximumObservedTime = 0;
    void Consume(const CapturedProbe& probe);
    void Flush(std::vector<CapturedEvent>& output, bool final);
};
} // namespace procmon::freebsd::app
