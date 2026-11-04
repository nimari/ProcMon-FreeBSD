// SPDX-License-Identifier: MIT
#include "output.h"
#include <stdexcept>
namespace procmon::freebsd::app
{
namespace
{
void String(std::ostream& out,const std::string& bytes)
{
    constexpr char digits[] = "0123456789abcdef"; out << '"';
    for (unsigned char byte : bytes)
    { if (byte == '"' || byte == '\\') out << '\\' << static_cast<char>(byte);
      else if (byte < 32 || byte >= 127) out << "\\u00" << digits[byte >> 4] << digits[byte & 15];
      else out << static_cast<char>(byte); }
    out << '"';
}
template<class T> void Optional(std::ostream& out,const std::optional<T>& value) { if (value) out << *value; else out << "null"; }
}
void Dump(NativeStorage& storage,const std::vector<pid_t>& pids,const std::vector<Event>& events,std::ostream& out)
{
    out << "{\"type\":\"capture\",\"platform\":\"FreeBSD-amd64\",\"version\":1,\"string_encoding\":\"byte-codepoints\",\"metadata\":{";
    bool first = true; for (const auto& item : storage.Metadata())
    { if (!first) out << ','; first = false; String(out,item.first); out << ':'; String(out,item.second); } out << "}}\n";
    storage.Visit(pids,events,[&](const ITelemetry& row)
    {
        const auto& event = *row.native;
        out << "{\"type\":\"event\",\"version\":1,\"pid\":" << event.pid << ",\"tid\":" << event.tid << ",\"uid\":" << event.uid << ",\"gid\":" << event.gid
            << ",\"raw_start_ns\":" << event.rawStart << ",\"timestamp_ns\":"; Optional(out,event.timestamp);
        out << ",\"duration_ns\":"; Optional(out,event.duration); out << ",\"result\":"; Optional(out,event.result);
        out << ",\"errno_bits\":"; Optional(out,event.errnoBits); out << ",\"state\":"; String(out,StateName(event.state));
        out << ",\"entry_present\":" << (event.entryPresent ? "true" : "false") << ",\"return_present\":" << (event.returnPresent ? "true" : "false")
            << ",\"syscall\":"; String(out,event.syscall); out << ",\"command\":"; String(out,event.command);
        out << ",\"arguments\":["; first = true;
        for (const auto& argument : event.arguments)
        {
            if (!first) out << ','; first = false; out << "{\"name\":"; String(out,argument.name); out << ",\"type\":"; String(out,argument.type);
            out << ",\"raw\":" << argument.raw << ",\"text\":"; if (argument.text) String(out,*argument.text); else out << "null";
            out << ",\"at_limit\":" << (argument.atLimit ? "true" : "false") << '}';
        }
        out << "],\"stack\":["; first = true; for (auto address : event.stack) { if (!first) out << ','; first = false; out << address; }
        out << "],\"symbols\":["; first = true; for (const auto& symbol : event.symbols) { if (!first) out << ','; first = false; String(out,symbol); }
        out << "]}\n";
    });
    out.flush(); if (!out) throw std::runtime_error("trace dump output failed");
}
}
