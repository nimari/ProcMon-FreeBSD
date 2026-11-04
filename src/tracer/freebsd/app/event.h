// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace procmon::freebsd::app
{
enum class EventState : std::uint8_t { Completed, EntryOnly, Restarted, ControlTransfer, Cancelled, Incomplete };
struct Argument
{
    std::string name, type;
    std::uint64_t raw = 0;
    std::optional<std::string> text;
    bool atLimit = false;
};
struct EventData
{
    std::uint64_t pid = 0, tid = 0, uid = 0, gid = 0, rawStart = 0;
    std::optional<std::uint64_t> timestamp, duration, errnoBits;
    std::optional<std::int64_t> result;
    EventState state = EventState::Incomplete;
    bool entryPresent = false, returnPresent = false;
    std::string syscall, command;
    std::vector<Argument> arguments;
    std::vector<std::uint64_t> stack;
    std::vector<std::string> symbols;
};
std::string StateName(EventState state);
std::string Escape(const std::string& bytes);
std::string Details(const EventData& event);
std::vector<std::uint8_t> Encode(const EventData& event);
EventData Decode(const void* bytes, std::size_t size);
} // namespace procmon::freebsd::app
