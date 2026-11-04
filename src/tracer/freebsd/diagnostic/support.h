// SPDX-License-Identifier: MIT
#pragma once
#include "../native_capture.h"
#include <charconv>
#include <limits>
#include <ostream>
#include <stdexcept>
#include <string_view>

namespace procmon::freebsd::diagnostic
{
struct Options
{
    CaptureConfiguration capture;
    std::uint64_t durationMs = 0; // Zero means wait for SIGINT/SIGTERM.
    bool help = false;
};
struct TargetStatus
{
    bool validated = false;
    std::optional<std::uint64_t> startSeconds, startMicroseconds;
    std::optional<int> exitStatus; // Raw wait(2) status from NOTE_EXIT, not a driver exit code.
    std::string stopCause;
};
inline std::uint64_t Positive(std::string_view text, std::uint64_t maximum)
{
    std::uint64_t result = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    if (text.empty() || parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
        result == 0 || result > maximum) throw std::invalid_argument("invalid positive integer");
    return result;
}
inline Options Parse(int argc, const char* const* argv)
{
    Options options;
    options.capture.operations = {NativeOperation::OpenAt, NativeOperation::Read, NativeOperation::Write};
    bool pid = false, events = false, duration = false;
    if (argc == 2 && std::string_view(argv[1]) == "--help") { options.help = true; return options; }
    for (int index = 1; index < argc; ++index)
    {
        const std::string_view option = argv[index];
        if (++index == argc) throw std::invalid_argument("option requires a value");
        const std::string_view value = argv[index];
        if (option == "--pid" && !pid)
        {
            options.capture.targetPid = Positive(value, std::numeric_limits<std::int32_t>::max());
            pid = true;
        }
        else if (option == "--duration-ms" && !duration)
        { options.durationMs = Positive(value, 86400000); duration = true; }
        else if (option == "--events" && !events)
        {
            options.capture.operations.clear();
            std::size_t start = 0;
            do
            {
                const auto end = value.find(',', start);
                const auto name = value.substr(start, end == value.npos ? end : end - start);
                NativeOperation operation;
                if (name == "openat") operation = NativeOperation::OpenAt;
                else if (name == "read") operation = NativeOperation::Read;
                else if (name == "write") operation = NativeOperation::Write;
                else throw std::invalid_argument("events must be comma-separated openat,read,write");
                bool duplicate = false;
                for (auto existing : options.capture.operations) duplicate |= existing == operation;
                if (!duplicate) options.capture.operations.push_back(operation);
                if (end == value.npos) break;
                start = end + 1;
            } while (true);
            events = true;
        }
        else throw std::invalid_argument("unknown or repeated option");
    }
    if (!pid) throw std::invalid_argument("--pid is required");
    return options;
}
// ASCII-only, reversible byte encoding: every non-ASCII byte becomes \u00XX.
// Consumers recover bytes by mapping JSON string code points 0..255 to bytes;
// no claim is made that paths/messages are UTF-8 or text in another encoding.
inline void String(std::ostream& out, std::string_view value)
{
    constexpr char hex[] = "0123456789abcdef";
    out << '"';
    for (unsigned char byte : value)
    {
        if (byte == '"' || byte == '\\') out << '\\' << static_cast<char>(byte);
        else if (byte < 32 || byte >= 127)
            out << "\\u00" << hex[byte >> 4] << hex[byte & 15];
        else out << static_cast<char>(byte);
    }
    out << '"';
}
template<class T> inline void Optional(std::ostream& out, const std::optional<T>& value)
{ if (value) out << *value; else out << "null"; }
inline const char* Operation(NativeOperation value)
{
    switch (value) { case NativeOperation::OpenAt: return "openat";
        case NativeOperation::Read: return "read"; case NativeOperation::Write: return "write"; }
    throw std::logic_error("unsupported operation");
}
inline const char* State(NativeEventState value)
{
    switch (value) { case NativeEventState::Completed: return "completed";
        case NativeEventState::Cancelled: return "cancelled"; case NativeEventState::Incomplete: return "incomplete"; }
    throw std::logic_error("unsupported event state");
}
inline const char* Reason(CaptureEndReason value)
{
    switch (value) { case CaptureEndReason::None: return "none";
        case CaptureEndReason::Completed: return "completed"; case CaptureEndReason::Cancelled: return "cancelled";
        case CaptureEndReason::Failure: return "failure"; case CaptureEndReason::Abandoned: return "abandoned"; }
    throw std::logic_error("unsupported end reason");
}
inline void Prefix(std::ostream& out, const char* type)
{ out << "{\"schema\":\"procmon-freebsd-diagnostic\",\"version\":1,\"type\":\"" << type << '"'; }
inline void Target(std::ostream& out, const TargetStatus* target)
{
    if (!target) return;
    out << ",\"target\":{\"validated\":" << (target->validated ? "true" : "false")
        << ",\"abi\":"; if (target->validated) String(out, "FreeBSD ELF64"); else out << "null";
    out << ",\"start_seconds\":"; Optional(out, target->startSeconds);
    out << ",\"start_microseconds\":"; Optional(out, target->startMicroseconds);
    out << ",\"exit_status\":"; Optional(out, target->exitStatus);
    out << ",\"stop_cause\":"; String(out, target->stopCause); out << '}';
}
inline void Ready(std::ostream& out, const CaptureReport& report, const Options& options, const TargetStatus* target = nullptr)
{
    Prefix(out, "ready");
    out << ",\"platform\":\"freebsd-amd64\",\"clock\":\"dtrace-session-ns\",\"string_encoding\":\"byte-codepoints\""
        << ",\"target_pid\":" << report.targetPid << ",\"monitor_pid\":" << report.monitorPid
        << ",\"duration_ms\":" << options.durationMs << ",\"events\":[";
    bool first = true;
    for (auto operation : options.capture.operations)
    { if (!first) out << ','; String(out, Operation(operation)); first = false; }
    out << ']'; Target(out, target); out << "}\n";
}
inline void Event(std::ostream& out, const NativeEvent& event)
{
    Prefix(out, "event");
    out << ",\"pid\":" << event.pid << ",\"tid\":" << event.tid << ",\"operation\":";
    String(out, Operation(event.operation)); out << ",\"state\":"; String(out, State(event.state));
    out << ",\"clock\":\"dtrace-session-ns\",\"correlation_start_ns\":" << event.correlationStartNs
        << ",\"entry_present\":" << (event.entryPresent ? "true" : "false")
        << ",\"return_present\":" << (event.returnPresent ? "true" : "false") << ",\"raw_entry_ns\":";
    Optional(out, event.rawEntryNs); out << ",\"timestamp_ns\":"; Optional(out, event.timestampNs);
    out << ",\"duration_ns\":"; Optional(out, event.durationNs);
    out << ",\"result\":"; Optional(out, event.result); out << ",\"errno\":"; Optional(out, event.error);
    out << ",\"entry_cpu\":"; Optional(out, event.entryCpu); out << ",\"return_cpu\":"; Optional(out, event.returnCpu);
    out << ",\"descriptor\":" << event.arguments.descriptor << ",\"third\":" << event.arguments.third << ",\"path\":";
    if (event.arguments.path)
    {
        out << "{\"bytes\":"; String(out, event.arguments.path->text);
        out << ",\"at_capture_limit\":" << (event.arguments.path->atCaptureLimit ? "true" : "false") << '}';
    }
    else out << "null";
    out << ",\"return_diagnostic\":";
    if (event.returned) out << "{\"result\":" << event.returned->result << ",\"errno_bits\":"
        << event.returned->errnoBits << ",\"duration_ns\":" << event.returned->durationNs << '}';
    else out << "null";
    out << "}\n";
}
inline void Notice(std::ostream& out, const SessionNotice& notice)
{
    Prefix(out, "notice"); out << ",\"kind\":\"" << (notice.kind == NoticeKind::Drop ? "drop" : "runtime_error")
        << "\",\"detail\":" << notice.detail << ",\"count\":" << notice.count << ",\"message\":";
    String(out, notice.message); out << "}\n";
}
inline void Summary(std::ostream& out, const CaptureReport& report, int signal, const TargetStatus* target = nullptr)
{
    Prefix(out, "summary"); out << ",\"target_pid\":" << report.targetPid << ",\"monitor_pid\":" << report.monitorPid
        << ",\"reason\":"; String(out, Reason(report.reason));
    out << ",\"complete\":" << (report.complete ? "true" : "false") << ",\"signal\":" << signal
        << ",\"stop_requested\":" << (report.stopRequested ? "true" : "false")
        << ",\"cancellation_requested\":" << (report.cancellationRequested ? "true" : "false")
        << ",\"diagnostic\":"; String(out, report.diagnostic);
    const auto& session = report.session;
    out << ",\"session\":{\"attempted\":" << (session.attempted ? "true" : "false")
        << ",\"opened\":" << (session.opened ? "true" : "false") << ",\"started\":" << (session.started ? "true" : "false")
        << ",\"stopped\":" << (session.stopped ? "true" : "false") << ",\"drained\":" << (session.drained ? "true" : "false")
        << ",\"closed\":" << (session.closed ? "true" : "false") << ",\"failed\":" << (session.failed ? "true" : "false")
        << ",\"discarded\":" << (session.discarded ? "true" : "false") << ",\"probes\":" << session.probes
        << ",\"data_records\":" << session.dataRecords << ",\"zero_records\":" << session.zeroRecords
        << ",\"runtime_errors\":" << session.runtimeErrors << ",\"drops\":" << session.drops << ",\"diagnostic\":";
    String(out, session.diagnostic); out << "},\"decoder\":";
    if (report.decoder)
    {
        const auto& decoder = *report.decoder;
        out << "{\"finalized\":" << (decoder.finalized ? "true" : "false")
            << ",\"complete\":" << (decoder.complete ? "true" : "false") << ",\"start_ns\":";
        Optional(out, decoder.startNs); out << ",\"end_ns\":"; Optional(out, decoder.endNs);
        out << ",\"completed\":" << decoder.completed << ",\"cancelled\":" << decoder.cancelled
            << ",\"incomplete\":" << decoder.incomplete << ",\"runtime_errors\":" << decoder.runtimeErrors
            << ",\"drops\":" << decoder.drops << ",\"issue\":";
        if (decoder.issue)
        { out << "{\"kind\":" << static_cast<int>(decoder.issue->kind) << ",\"message\":";
          String(out, decoder.issue->message); out << '}'; }
        else out << "null";
        out << '}';
    }
    else out << "null";
    Target(out, target); out << "}\n";
}
} // namespace procmon::freebsd::diagnostic
