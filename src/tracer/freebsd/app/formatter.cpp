// SPDX-License-Identifier: MIT
#include "../../../display/event_formatter.h"
#include <iomanip>
#include <sstream>
#include <cstring>
using namespace procmon::freebsd::app;
std::string EventFormatter::GetTimestamp(ITelemetry& event)
{
    if (!event.native || !event.native->timestamp) return "[unknown]";
    const auto ns = *event.native->timestamp; std::ostringstream out;
    out << '+' << ns / 1000000000 << '.' << std::setw(3) << std::setfill('0') << (ns / 1000000) % 1000; return out.str();
}
std::string EventFormatter::GetPID(ITelemetry& event) { return std::to_string(event.pid); }
std::string EventFormatter::GetProcess(ITelemetry& event) { return event.processName; }
std::string EventFormatter::GetOperation(ITelemetry& event) { return Escape(event.syscall); }
std::string EventFormatter::GetDuration(ITelemetry& event)
{ if (!event.native || !event.native->duration) return "[unknown]"; std::ostringstream out; out << std::fixed << std::setprecision(3) << *event.native->duration / 1000000.0; return out.str(); }
std::string EventFormatter::GetResult(ITelemetry& event)
{
    if (!event.native) return "[unknown]"; const auto& data = *event.native;
    if (data.state != EventState::Completed || !data.result || !data.errnoBits) return '[' + StateName(data.state) + ']';
    if (*data.errnoBits) return std::to_string(*data.result) + " errno=" + std::to_string(*data.errnoBits) + " (" + std::strerror(static_cast<int>(*data.errnoBits)) + ')';
    if (data.syscall == "mmap" || data.syscall == "shmat") { std::ostringstream out; out << "0x" << std::hex << static_cast<std::uint64_t>(*data.result); return out.str(); }
    return std::to_string(*data.result);
}
std::string EventFormatter::GetDetails(ITelemetry& event) { return event.native ? Details(*event.native) : "[typed arguments unavailable]"; }
