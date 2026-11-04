// SPDX-License-Identifier: MIT
#include "../../src/tracer/freebsd/native_event_decoder.h"
#include <sys/types.h>
#include <dtrace.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <utility>

using namespace procmon::freebsd;
static unsigned int checks;
static void Check(bool value)
{
    ++checks;
    if (!value) throw std::runtime_error("check " + std::to_string(checks) + " failed");
}
static CapturedRecord Scalar(std::uint64_t value)
{
    CapturedRecord record;
    record.action = DTRACEACT_DIFEXPR;
    record.bytes.resize(8);
    std::memcpy(record.bytes.data(), &value, 8);
    return record;
}
static CapturedProbe Probe(const std::string& function, const std::string& name,
    std::initializer_list<std::uint64_t> values, bool path = false, int cpu = 0)
{
    CapturedProbe probe;
    probe.provider = function.empty() ? "dtrace" : "syscall";
    probe.module = function.empty() ? "" : "freebsd";
    probe.function = function; probe.name = name; probe.cpu = cpu;
    for (auto value : values) probe.records.push_back(Scalar(value));
    if (path)
    {
        CapturedRecord text;
        text.action = DTRACEACT_DIFEXPR;
        text.bytes.assign(65, 0); text.bytes[0] = '-';
        probe.records.push_back(std::move(text));
    }
    return probe;
}
static CapturedProbe Begin() { return Probe("", "BEGIN", {42, 1000}); }
static CapturedProbe End() { return Probe("", "END", {42, 2000}); }
static CapturedProbe Entry(std::uint64_t tid = 43, std::uint64_t time = 1100)
{ return Probe("read", "entry", {42, tid, time, 3, 8}, true); }
static CapturedProbe Return(std::uint64_t tid = 43, std::uint64_t time = 1100,
    std::int64_t result = 8, std::uint64_t error = 0, std::uint64_t duration = 50)
{ return Probe("read", "return", {42, tid, time, duration, static_cast<std::uint64_t>(result), error, 3, 8}, true, 1); }
static SessionStatus Status(const SessionBatch& batch)
{
    SessionStatus status;
    status.attempted = status.opened = status.started = status.stopped = status.drained = status.closed = true;
    status.probes = batch.probes.size();
    for (const auto& probe : batch.probes)
        for (const auto& record : probe.records)
            ++(record.bytes.empty() ? status.zeroRecords : status.dataRecords);
    for (const auto& notice : batch.notices)
        (notice.kind == NoticeKind::Drop ? status.drops : status.runtimeErrors) += notice.count;
    return status;
}
struct Result { std::vector<NativeEvent> events; DecoderReport report; };
static Result Run(std::vector<CapturedProbe> probes, bool cancel = false,
    std::size_t capacity = 4096, std::vector<SessionNotice> notices = {})
{
    SessionBatch batch{PollOutcome::Done, std::move(probes), std::move(notices)};
    NativeEventDecoder decoder(42, capacity);
    Result result{decoder.Consume(batch).events, {}};
    auto final = decoder.Finish(Status(batch), cancel);
    for (auto& event : final.events) result.events.push_back(std::move(event));
    result.report = decoder.Report();
    return result;
}
static void Issue(std::vector<CapturedProbe> probes, DecodeIssueKind kind)
{
    auto result = Run(std::move(probes));
    Check(result.report.finalized && !result.report.complete && result.report.issue &&
        result.report.issue->kind == kind);
}

int main()
{
    try
    {
        auto normal = Run({Begin(), Entry(), Return(), End()});
        Check(normal.report.complete && normal.events.size() == 1);
        const auto& event = normal.events[0];
        Check(event.state == NativeEventState::Completed && event.timestampNs == 100 &&
            event.durationNs == 50 && event.result == 8 && event.error == 0 &&
            event.entryCpu == 0 && event.returnCpu == 1 && !event.arguments.path);
        auto negative = Run({Begin(), Entry(), Return(43, 1100, -42), End()}, true);
        Check(!negative.report.complete && negative.events[0].state == NativeEventState::Completed &&
            negative.events[0].result == -42 && negative.events[0].error == 0);
        auto error = Run({Begin(), Entry(), Return(43, 1100, -1, 9), End()});
        Check(error.events[0].result == -1 && error.events[0].error == 9);
        auto reordered = Run({Return(), End(), Entry(), Begin()});
        Check(reordered.report.complete && reordered.events[0].timestampNs == 100);
        auto threads = Run({Begin(), Entry(), Entry(44, 1150), Return(44, 1150), Return(), End()});
        Check(threads.report.complete && threads.events.size() == 2 && threads.events[0].tid != threads.events[1].tid);
        auto repeated = Run({Begin(), Entry(), Return(), Entry(43, 1200), Return(43, 1200), End()});
        Check(repeated.report.complete && repeated.events.size() == 2);
        for (bool cancel : {false, true})
        {
            auto missing = Run({Begin(), Entry(), End()}, cancel);
            Check(!missing.report.complete && !missing.report.issue && missing.events.size() == 1);
            Check(missing.events[0].state == (cancel ? NativeEventState::Cancelled : NativeEventState::Incomplete) &&
                missing.events[0].timestampNs == 100 && !missing.events[0].returned &&
                !missing.events[0].durationNs && !missing.events[0].result && !missing.events[0].error);
            auto sentinel = Run({Begin(), Entry(), Return(43, 1100, -1, UINT64_MAX), End()}, cancel);
            Check(sentinel.events[0].state == (cancel ? NativeEventState::Cancelled : NativeEventState::Incomplete) &&
                sentinel.events[0].returned->errnoBits == UINT64_MAX && !sentinel.events[0].result);
        }
        auto orphan = Run({Begin(), Return(), End()}, true);
        Check(orphan.events[0].state == NativeEventState::Incomplete && !orphan.events[0].entryPresent &&
            !orphan.events[0].timestampNs && !orphan.events[0].rawEntryNs && orphan.events[0].returned.has_value() &&
            orphan.events[0].correlationStartNs == 1100);
        auto wideError = Run({Begin(), Entry(), Return(43, 1100, -1, std::uint64_t(INT32_MAX) + 1), End()});
        Check(wideError.events[0].state == NativeEventState::Incomplete && !wideError.events[0].error);
        Issue({Begin(), Entry(), Entry(), End()}, DecodeIssueKind::DuplicateRecord);
        Issue({Begin(), Return(), Return(), End()}, DecodeIssueKind::DuplicateRecord);
        Issue({Begin(), Entry(), Return(), Entry(), End()}, DecodeIssueKind::DuplicateRecord);
        Issue({Begin(), Begin(), End()}, DecodeIssueKind::DuplicateRecord);
        auto mismatch = Return(); mismatch.records[6] = Scalar(4);
        Issue({Begin(), Entry(), mismatch, End()}, DecodeIssueKind::MalformedRecord);
        auto wrongPid = Entry(); wrongPid.records[0] = Scalar(99);
        Issue({Begin(), wrongPid, End()}, DecodeIssueKind::MalformedRecord);
        auto wrongTid = Entry(0); Issue({Begin(), wrongTid, End()}, DecodeIssueKind::MalformedRecord);
        auto wideFd = Entry(); wideFd.records[3] = Scalar(std::uint64_t(INT32_MAX) + 1);
        Issue({Begin(), wideFd, End()}, DecodeIssueKind::MalformedRecord);
        auto wrongWidth = Entry(); wrongWidth.records[0].bytes.resize(7);
        Issue({Begin(), wrongWidth, End()}, DecodeIssueKind::MalformedRecord);
        auto unterminated = Entry(); unterminated.records.back().bytes.assign(65, 'x');
        Issue({Begin(), unterminated, End()}, DecodeIssueKind::MalformedRecord);
        auto unknown = Entry(); unknown.function = "sendfile";
        Issue({Begin(), unknown, End()}, DecodeIssueKind::UnsupportedSchema);
        auto abi = Entry(); abi.module = "freebsd32";
        Issue({Begin(), abi, End()}, DecodeIssueKind::UnsupportedSchema);
        auto action = Entry(); action.records[0].action = DTRACEACT_USTACK;
        Issue({Begin(), action, End()}, DecodeIssueKind::UnsupportedSchema);
        Issue({Begin(), Entry(43, 999), Return(43, 999), End()}, DecodeIssueKind::Clock);
        Issue({Begin(), Entry(43, 2001), Return(43, 2001), End()}, DecodeIssueKind::Clock);
        Issue({Begin(), Entry(), Return(43, 1100, 1, 0, UINT64_MAX), End()}, DecodeIssueKind::Clock);
        Issue({Begin(), Entry(), Return(43, 1100, 1, 0, 901), End()}, DecodeIssueKind::Clock);
        Issue({Entry(), Return(), End()}, DecodeIssueKind::Clock);
        Issue({Begin(), Entry(), Return()}, DecodeIssueKind::Clock);
        auto capacity = Run({Begin(), Entry(), Entry(44), End()}, false, 1);
        Check(capacity.report.issue && capacity.report.issue->kind == DecodeIssueKind::Capacity);
        auto streaming = Run({Begin(), Entry(), Return(), Entry(44), Return(44), End()}, false, 1);
        Check(streaming.report.complete && streaming.events.size() == 2);
        NativeEventDecoder boundedStream(42, 1, 1);
        SessionBatch all{PollOutcome::Done, {Begin()}, {}};
        boundedStream.Consume({PollOutcome::Okay, {Begin()}, {}});
        for (unsigned int index = 0; index < 20; ++index)
        {
            auto entry = Entry(43, 1100 + index * 10), returned = Return(43, 1100 + index * 10);
            auto output = boundedStream.Consume({PollOutcome::Okay, {entry, returned}, {}});
            Check(output.events.size() == 1 && !output.issue);
            all.probes.push_back(std::move(entry)); all.probes.push_back(std::move(returned));
        }
        all.probes.push_back(End());
        boundedStream.Consume({PollOutcome::Done, {End()}, {}});
        Check(boundedStream.Finish(Status(all), false).events.empty());
        Check(boundedStream.Report().complete && boundedStream.Report().completed == 20);
        auto pathEntry = Entry(), pathReturn = Return();
        pathEntry.function = pathReturn.function = "openat";
        pathEntry.records.back().bytes.assign(65, 'a'); pathEntry.records.back().bytes[64] = 0;
        pathReturn.records.back() = pathEntry.records.back();
        auto paths = Run({Begin(), pathEntry, pathReturn, End()});
        Check(paths.report.complete && paths.events[0].arguments.path->atCaptureLimit &&
            paths.events[0].arguments.path->text.size() == 64);
        auto assignment = Entry(); CapturedRecord empty; empty.action = DTRACEACT_DIFEXPR;
        assignment.records.insert(assignment.records.begin(), empty);
        Check(Run({Begin(), assignment, Return(), End()}).report.complete);
        auto gaps = Run({Begin(), Entry(), Return(), End()}, false, 4096,
            {{NoticeKind::Drop, 0, 2, "drop"}, {NoticeKind::RuntimeError, 1, 1, "fault"}});
        Check(!gaps.report.complete && !gaps.report.issue && gaps.report.drops == 2 &&
            gaps.report.runtimeErrors == 1 && gaps.events[0].state == NativeEventState::Completed);
        SessionBatch batch{PollOutcome::Done, {Begin(), Entry(), Return(), End()}, {}};
        auto status = Status(batch); status.discarded = true;
        NativeEventDecoder discarded(42); discarded.Consume(batch); discarded.Finish(status, false);
        Check(discarded.Report().issue->kind == DecodeIssueKind::Transport);
        NativeEventDecoder lost(42); lost.Consume(batch); status = Status(batch); ++status.probes;
        lost.Finish(status, false); Check(lost.Report().issue->kind == DecodeIssueKind::Transport);
        bool misuse = false;
        try { lost.Consume(batch); } catch (const std::logic_error&) { misuse = true; }
        Check(misuse);
        std::cout << "PASS: " << checks << " native decoder boundary/correlation checks\n";
        return 0;
    }
    catch (const std::exception& error) { std::cerr << "FAIL: " << error.what() << '\n'; return 1; }
}
