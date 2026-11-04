// SPDX-License-Identifier: MIT
#include "../../src/tracer/freebsd/diagnostic/support.h"
#include <iostream>
#include <sstream>
#include <vector>
namespace d = procmon::freebsd::diagnostic;
using namespace procmon::freebsd;
static unsigned checks;
static void Check(bool value)
{ ++checks; if (!value) throw std::runtime_error("diagnostic support check failed"); }
static d::Options Parse(std::initializer_list<const char*> arguments)
{ std::vector<const char*> values(arguments); return d::Parse(static_cast<int>(values.size()), values.data()); }
int main()
{
    Check(Parse({"pilot", "--help"}).help);
    auto options = Parse({"pilot", "--pid", "2147483647", "--events", "write,read,write", "--duration-ms", "86400000"});
    Check(options.capture.targetPid == 2147483647 && options.durationMs == 86400000);
    Check(options.capture.operations == std::vector<NativeOperation>{NativeOperation::Write, NativeOperation::Read});
    Check(Parse({"pilot", "--pid", "1"}).capture.operations.size() == 3);
    Check(Parse({"pilot", "--pid", "0001"}).capture.targetPid == 1);
    for (auto value : {"", "0", "-1", "+1", " 1", "1 ", "1x", "2147483648", "18446744073709551616"})
    {
        bool rejected = false;
        try { Parse({"pilot", "--pid", value}); } catch (const std::invalid_argument&) { rejected = true; }
        Check(rejected);
    }
    for (auto value : {"", "read,", ",read", "read,,write", "READ", "open", " read", "read;system"})
    {
        bool rejected = false;
        try { Parse({"pilot", "--pid", "1", "--events", value}); } catch (const std::invalid_argument&) { rejected = true; }
        Check(rejected);
    }
    for (auto arguments : {std::vector<const char*>{"pilot"}, {"pilot", "--pid"},
        {"pilot", "--pid", "1", "--pid", "2"}, {"pilot", "--pid", "1", "--wat", "x"},
        {"pilot", "--help", "--pid", "1"}, {"pilot", "--pid", "1", "--duration-ms", "0"},
        {"pilot", "--pid", "1", "--duration-ms", "86400001"},
        {"pilot", "--pid", "1", "--events", "read", "--events", "write"},
        {"pilot", "--pid", "1", "--duration-ms", "1", "--duration-ms", "2"}})
    {
        bool rejected = false;
        try { d::Parse(static_cast<int>(arguments.size()), arguments.data()); }
        catch (const std::invalid_argument&) { rejected = true; }
        Check(rejected);
    }
    std::string bytes;
    for (unsigned index = 0; index < 256; ++index) bytes += static_cast<char>(index);
    std::ostringstream encoded;
    d::String(encoded, bytes);
    Check(encoded.str().find("\\u0000") != std::string::npos);
    Check(encoded.str().find("\\u00ff") != std::string::npos);
    Check(encoded.str().find("\\\"") != std::string::npos && encoded.str().find("\\\\") != std::string::npos);
    std::cout << "CHECKS\t" << checks << '\n' << encoded.str() << '\n';
    NativeEvent event;
    event.pid = 12; event.tid = 34; event.operation = NativeOperation::OpenAt;
    event.arguments.descriptor = -100; event.arguments.third = 18446744073709551615ULL;
    event.arguments.path = CapturedPath{bytes, true};
    event.returned = NativeReturnDiagnostic{-1, 18446744073709551615ULL, 99};
    d::Event(std::cout, event);
    event.state = NativeEventState::Completed; event.entryPresent = event.returnPresent = true;
    event.rawEntryNs = 110; event.timestampNs = 10; event.durationNs = 5;
    event.result = -2; event.error = 0; event.entryCpu = 0; event.returnCpu = 1;
    event.returned.reset(); event.arguments.path.reset(); d::Event(std::cout, event);
    event.state = NativeEventState::Cancelled; event.result.reset(); event.error.reset();
    event.durationNs.reset(); event.returnPresent = false; event.returnCpu.reset(); d::Event(std::cout, event);
    CaptureReport report; report.targetPid = 12; report.monitorPid = 56;
    report.reason = CaptureEndReason::Failure; report.session.closed = true;
    report.decoder.emplace(); report.decoder->finalized = true;
    report.decoder->issue = DecodeIssue{DecodeIssueKind::Transport, bytes};
    d::Summary(std::cout, report, 2);
    d::Ready(std::cout, report, options);
    d::Notice(std::cout, {NoticeKind::Drop, 8, 7, bytes});
    d::Notice(std::cout, {NoticeKind::RuntimeError, 1, 1, "fault"});
}
