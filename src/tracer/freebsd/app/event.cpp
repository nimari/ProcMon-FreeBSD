// SPDX-License-Identifier: MIT
#include "event.h"
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace procmon::freebsd::app
{
std::string StateName(EventState state)
{
    switch (state)
    {
        case EventState::Completed: return "completed";
        case EventState::EntryOnly: return "entry-only";
        case EventState::Restarted: return "restart";
        case EventState::ControlTransfer: return "control-transfer";
        case EventState::Cancelled: return "cancelled";
        case EventState::Incomplete: return "incomplete";
    }
    throw std::runtime_error("unknown FreeBSD event state");
}
std::string Escape(const std::string& bytes)
{
    std::ostringstream out;
    for (unsigned char value : bytes)
    {
        if (value >= 32 && value < 127 && value != '\\' && value != '"') out << static_cast<char>(value);
        else if (value == '\\' || value == '"') out << '\\' << static_cast<char>(value);
        else out << "\\x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(value) << std::dec;
    }
    return out.str();
}
std::string Details(const EventData& event)
{
    std::ostringstream out;
    out << "tid=" << event.tid << " uid=" << event.uid << " state=" << StateName(event.state);
    for (const auto& argument : event.arguments)
    {
        out << " " << argument.name << "=";
        if (argument.text) out << '"' << Escape(*argument.text) << '"' << (argument.atLimit ? "[limit]" : "");
        else if (argument.type.find('*') != std::string::npos || argument.type.find("addr") != std::string::npos)
            out << "0x" << std::hex << argument.raw << std::dec << "[no snapshot]";
        else if (argument.type == "int" || argument.type == "pid_t" || argument.type == "int32_t" || argument.type == "lwpid_t")
            out << static_cast<std::int32_t>(argument.raw);
        else if (argument.type == "long" || argument.type == "off_t" || argument.type == "ssize_t" || argument.type == "int64_t")
        { std::int64_t value; std::memcpy(&value, &argument.raw, 8); out << value; }
        else out << argument.raw;
    }
    return out.str();
}
namespace
{
struct Writer
{
    std::vector<std::uint8_t> bytes;
    void Number(std::uint64_t value) { for (unsigned index = 0; index < 8; ++index) { bytes.push_back(value & 255); value >>= 8; } }
    void Text(const std::string& value)
    {
        if (value.size() > 4096) throw std::runtime_error("FreeBSD event string exceeds format bound");
        Number(value.size()); bytes.insert(bytes.end(), value.begin(), value.end());
    }
    void Optional(const std::optional<std::uint64_t>& value)
    { Number(value.has_value()); if (value) Number(*value); }
};
struct Reader
{
    const std::uint8_t* data; std::size_t remaining;
    std::uint64_t Number()
    {
        if (remaining < 8) throw std::runtime_error("truncated FreeBSD event");
        std::uint64_t value = 0;
        for (unsigned index = 0; index < 8; ++index) value |= static_cast<std::uint64_t>(data[index]) << (8 * index);
        data += 8; remaining -= 8; return value;
    }
    bool Flag() { auto value = Number(); if (value > 1) throw std::runtime_error("invalid FreeBSD event flag"); return value != 0; }
    std::string Text()
    {
        auto count = Number(); if (count > 4096 || count > remaining) throw std::runtime_error("invalid FreeBSD event string");
        std::string value(reinterpret_cast<const char*>(data), count); data += count; remaining -= count; return value;
    }
    std::optional<std::uint64_t> Optional() { return Flag() ? std::optional<std::uint64_t>(Number()) : std::nullopt; }
};
}
std::vector<std::uint8_t> Encode(const EventData& event)
{
    if (event.arguments.size() > 8 || event.stack.size() > 32 || event.symbols.size() > event.stack.size())
        throw std::runtime_error("FreeBSD event collection exceeds format bound");
    (void)StateName(event.state);
    Writer out;
    out.Number(0x504d4642455631ULL); // PMFBEV1, independent of the Linux wire format.
    out.Number(static_cast<unsigned>(event.state)); out.Number(event.entryPresent); out.Number(event.returnPresent);
    for (auto value : {event.pid, event.tid, event.uid, event.gid, event.rawStart}) out.Number(value);
    out.Optional(event.timestamp); out.Optional(event.duration); out.Optional(event.errnoBits);
    out.Number(event.result.has_value()); if (event.result) { std::uint64_t bits; std::memcpy(&bits, &*event.result, 8); out.Number(bits); }
    out.Text(event.syscall); out.Text(event.command); out.Number(event.arguments.size());
    for (const auto& argument : event.arguments)
    { out.Text(argument.name); out.Text(argument.type); out.Number(argument.raw); out.Number(argument.text.has_value());
      if (argument.text) out.Text(*argument.text); out.Number(argument.atLimit); }
    out.Number(event.stack.size()); for (auto address : event.stack) out.Number(address);
    out.Number(event.symbols.size()); for (const auto& symbol : event.symbols) out.Text(symbol);
    if (out.bytes.size() > 131072) throw std::runtime_error("FreeBSD event payload exceeds format bound");
    return out.bytes;
}
EventData Decode(const void* bytes, std::size_t size)
{
    if (!bytes || size > 131072) throw std::runtime_error("invalid FreeBSD event payload");
    Reader in{static_cast<const std::uint8_t*>(bytes), size}; EventData event;
    if (in.Number() != 0x504d4642455631ULL) throw std::runtime_error("unsupported FreeBSD event version");
    auto state = in.Number(); if (state > static_cast<unsigned>(EventState::Incomplete)) throw std::runtime_error("invalid FreeBSD event state");
    event.state = static_cast<EventState>(state); event.entryPresent = in.Flag(); event.returnPresent = in.Flag();
    event.pid = in.Number(); event.tid = in.Number(); event.uid = in.Number(); event.gid = in.Number(); event.rawStart = in.Number();
    event.timestamp = in.Optional(); event.duration = in.Optional(); event.errnoBits = in.Optional();
    if (in.Flag()) { auto bits = in.Number(); std::int64_t value; std::memcpy(&value, &bits, 8); event.result = value; }
    event.syscall = in.Text(); event.command = in.Text(); auto count = in.Number();
    if (count > 8) throw std::runtime_error("invalid FreeBSD argument count");
    while (count--)
    { Argument argument; argument.name = in.Text(); argument.type = in.Text(); argument.raw = in.Number();
      if (in.Flag()) argument.text = in.Text(); argument.atLimit = in.Flag(); event.arguments.push_back(std::move(argument)); }
    count = in.Number(); if (count > 32) throw std::runtime_error("invalid FreeBSD stack count");
    while (count--) event.stack.push_back(in.Number());
    count = in.Number(); if (count > event.stack.size()) throw std::runtime_error("invalid FreeBSD symbol count");
    while (count--) event.symbols.push_back(in.Text());
    if (in.remaining) throw std::runtime_error("trailing FreeBSD event data");
    return event;
}
} // namespace procmon::freebsd::app
