// SPDX-License-Identifier: MIT
#include "native_event_decoder.h"

#if !defined(__FreeBSD__) || !defined(__amd64__)
#error "Native event decoding currently targets FreeBSD amd64 only"
#endif
#include <sys/types.h>
#include <dtrace.h>

#include <algorithm>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace procmon::freebsd
{
namespace
{
std::int64_t Signed(std::uint64_t bits)
{
    std::int64_t result;
    std::memcpy(&result, &bits, sizeof(result));
    return result;
}
bool SameArguments(const NativeArguments& a, const NativeArguments& b)
{
    return a.descriptor == b.descriptor && a.third == b.third &&
        a.path.has_value() == b.path.has_value() && (!a.path ||
        (a.path->text == b.path->text && a.path->atCaptureLimit == b.path->atCaptureLimit));
}
} // namespace

struct NativeEventDecoder::Impl
{
    using Key = std::tuple<std::uint64_t, std::uint64_t, NativeOperation, std::uint64_t>;
    std::uint64_t pid, probes = 0, dataRecords = 0, zeroRecords = 0;
    std::size_t maximumPending, recentLimit;
    std::map<Key, NativeEvent> pending;
    std::set<Key> retired;
    std::deque<Key> retirementOrder;
    std::optional<std::uint64_t> minimumTime, maximumTime;
    DecoderReport report;
    bool done = false;

    Impl(std::uint64_t target, std::size_t capacity, std::size_t history)
        : pid(target), maximumPending(capacity), recentLimit(history)
    {
        if (!pid || !capacity || !history)
            throw std::invalid_argument("decoder PID and capacities must be positive");
    }
    void Fail(DecodeIssueKind kind, const std::string& message)
    {
        if (!report.issue) report.issue = DecodeIssue{kind, message};
    }
    void Add(std::uint64_t& count, std::uint64_t amount)
    {
        if (amount > std::numeric_limits<std::uint64_t>::max() - count)
            Fail(DecodeIssueKind::Capacity, "decoder counter overflow");
        else count += amount;
    }
    void Time(std::uint64_t start, std::uint64_t end)
    {
        minimumTime = minimumTime ? std::min(*minimumTime, start) : start;
        maximumTime = maximumTime ? std::max(*maximumTime, end) : end;
    }
    void CheckClock()
    {
        if ((report.startNs && report.endNs && *report.endNs < *report.startNs) ||
            (report.startNs && minimumTime && *minimumTime < *report.startNs) ||
            (report.endNs && maximumTime && *maximumTime > *report.endNs))
            Fail(DecodeIssueKind::Clock, "records outside DTrace session clock bounds");
    }
    bool Fields(const CapturedProbe& probe, std::size_t scalars, bool path,
        std::vector<std::uint64_t>& values, std::string& text)
    {
        std::size_t field = 0;
        for (const auto& record : probe.records)
        {
            if (record.action != DTRACEACT_DIFEXPR)
            {
                Fail(DecodeIssueKind::UnsupportedSchema, "unsupported record action");
                return false;
            }
            if (record.bytes.empty()) continue;
            if (field >= scalars + path || record.bytes.size() != (field < scalars ? 8U : 65U))
            {
                Fail(DecodeIssueKind::MalformedRecord, "unexpected field order/width/count");
                return false;
            }
            if (field < scalars)
            {
                std::uint64_t value;
                std::memcpy(&value, record.bytes.data(), sizeof(value));
                values.push_back(value);
            }
            else
            {
                const auto* end = static_cast<const std::uint8_t*>(
                    std::memchr(record.bytes.data(), 0, record.bytes.size()));
                if (!end)
                {
                    Fail(DecodeIssueKind::MalformedRecord, "unterminated bounded path");
                    return false;
                }
                text.assign(reinterpret_cast<const char*>(record.bytes.data()),
                    static_cast<std::size_t>(end - record.bytes.data()));
            }
            ++field;
        }
        if (field != scalars + path || values.empty() || values[0] != pid)
        {
            Fail(DecodeIssueKind::MalformedRecord, "missing fields or wrong target PID");
            return false;
        }
        return true;
    }
    void Read(const CapturedProbe& probe)
    {
        std::vector<std::uint64_t> value;
        std::string text;
        if (probe.provider == "dtrace" && probe.module.empty() && probe.function.empty() &&
            (probe.name == "BEGIN" || probe.name == "END"))
        {
            if (!Fields(probe, 2, false, value, text)) return;
            auto& boundary = probe.name == "BEGIN" ? report.startNs : report.endNs;
            if (boundary) Fail(DecodeIssueKind::DuplicateRecord, "duplicate session boundary");
            else boundary = value[1];
            return;
        }
        if (probe.provider != "syscall" || probe.module != "freebsd")
        {
            Fail(DecodeIssueKind::UnsupportedSchema, "unsupported provider/ABI");
            return;
        }
        bool entry = probe.name == "entry";
        if (entry && (probe.function == "getpgid" || probe.function == "_exit"))
        {
            if (!Fields(probe, probe.function == "getpgid" ? 3 : 2, false, value, text)) return;
            if (probe.function == "getpgid")
            {
                if (value[2] != 0 && value[2] != pid)
                    Fail(DecodeIssueKind::MalformedRecord, "invalid fixture control marker");
                Time(value[1], value[1]);
            }
            return;
        }
        NativeOperation operation;
        if (probe.function == "openat") operation = NativeOperation::OpenAt;
        else if (probe.function == "read") operation = NativeOperation::Read;
        else if (probe.function == "write") operation = NativeOperation::Write;
        else
        {
            Fail(DecodeIssueKind::UnsupportedSchema, "unsupported syscall: " + probe.function);
            return;
        }
        if (!entry && probe.name != "return")
        {
            Fail(DecodeIssueKind::UnsupportedSchema, "unsupported syscall probe kind");
            return;
        }
        if (!Fields(probe, entry ? 5 : 8, true, value, text)) return;
        NativeArguments arguments;
        arguments.descriptor = Signed(value[entry ? 3 : 6]);
        arguments.third = value[entry ? 4 : 7];
        if (operation == NativeOperation::OpenAt)
            arguments.path = CapturedPath{text, text.size() == 64};
        if (!value[1] || probe.cpu < 0 || arguments.descriptor < INT32_MIN ||
            arguments.descriptor > INT32_MAX || (operation != NativeOperation::OpenAt && text != "-"))
        {
            Fail(DecodeIssueKind::MalformedRecord, "invalid TID/CPU/descriptor/path marker");
            return;
        }
        Key key{pid, value[1], operation, value[2]};
        if (retired.count(key))
        {
            Fail(DecodeIssueKind::DuplicateRecord, "recent completed key repeated");
            return;
        }
        auto found = pending.find(key);
        if (found == pending.end())
        {
            if (pending.size() >= maximumPending)
            {
                Fail(DecodeIssueKind::Capacity, "pending correlation capacity exceeded");
                return;
            }
            NativeEvent event;
            event.pid = pid; event.tid = value[1]; event.operation = operation;
            event.correlationStartNs = value[2];
            event.arguments = arguments;
            found = pending.emplace(key, std::move(event)).first;
        }
        auto& event = found->second;
        if ((entry ? event.entryPresent : event.returnPresent))
            Fail(DecodeIssueKind::DuplicateRecord, "entry or return repeated");
        else if (!SameArguments(event.arguments, arguments))
            Fail(DecodeIssueKind::MalformedRecord, "entry/return arguments disagree");
        else if (entry)
        {
            event.entryPresent = true; event.rawEntryNs = value[2]; event.entryCpu = probe.cpu;
            Time(value[2], value[2]);
        }
        else
        {
            event.returnPresent = true; event.returnCpu = probe.cpu;
            event.returned = NativeReturnDiagnostic{Signed(value[4]), value[5], value[3]};
        }
    }
    void Flush(DecodedBatch& output)
    {
        if (!report.startNs || report.issue) return;
        for (auto it = pending.begin(); it != pending.end();)
        {
            auto& event = it->second;
            if (!event.entryPresent || !event.returned || event.returned->errnoBits > INT32_MAX)
            { ++it; continue; }
            auto start = *event.rawEntryNs, duration = event.returned->durationNs;
            if (start < *report.startNs || duration > UINT64_MAX - start)
            {
                Fail(DecodeIssueKind::Clock, "invalid entry time or overflowing duration");
                return;
            }
            Time(start, start + duration);
            CheckClock();
            if (report.issue) return;
            event.timestampNs = start - *report.startNs;
            event.durationNs = duration; event.result = event.returned->result;
            event.error = static_cast<std::uint32_t>(event.returned->errnoBits);
            event.state = NativeEventState::Completed;
            retired.insert(it->first);
            retirementOrder.push_back(it->first);
            if (retirementOrder.size() > recentLimit)
            {
                retired.erase(retirementOrder.front()); retirementOrder.pop_front();
            }
            output.events.push_back(std::move(event));
            Add(report.completed, 1);
            it = pending.erase(it);
        }
    }
};

NativeEventDecoder::NativeEventDecoder(std::uint64_t pid, std::size_t pending, std::size_t history)
    : impl(std::make_unique<Impl>(pid, pending, history)) {}
NativeEventDecoder::~NativeEventDecoder() = default;

DecodedBatch NativeEventDecoder::Consume(const SessionBatch& batch)
{
    auto& self = *impl;
    if (self.report.finalized) throw std::logic_error("consume after decoder finalization");
    DecodedBatch output;
    if (self.report.issue) { output.issue = self.report.issue; return output; }
    if (self.done && (!batch.probes.empty() || !batch.notices.empty()))
        self.Fail(DecodeIssueKind::Protocol, "data after terminal batch");
    if (batch.outcome == PollOutcome::Error)
        self.Fail(DecodeIssueKind::Transport, "session polling failed");
    for (const auto& notice : batch.notices)
    {
        if (notice.kind == NoticeKind::Drop) self.Add(self.report.drops, notice.count);
        else if (notice.kind == NoticeKind::RuntimeError) self.Add(self.report.runtimeErrors, notice.count);
        else self.Fail(DecodeIssueKind::Protocol, "unknown session notice kind");
    }
    for (const auto& probe : batch.probes)
    {
        self.Add(self.probes, 1);
        for (const auto& record : probe.records)
            self.Add(record.bytes.empty() ? self.zeroRecords : self.dataRecords, 1);
        if (self.report.issue) break;
        self.Read(probe);
        self.CheckClock();
        self.Flush(output);
        if (self.report.issue) break;
    }
    if (batch.outcome == PollOutcome::Done) self.done = true;
    output.issue = self.report.issue;
    return output;
}

DecodedBatch NativeEventDecoder::Finish(const SessionStatus& session, bool cancellationRequested)
{
    auto& self = *impl;
    if (self.report.finalized) throw std::logic_error("decoder already finalized");
    self.report.cancellationRequested = cancellationRequested;
    if (!self.done || !session.started || !session.stopped || !session.drained || !session.closed ||
        session.failed || session.discarded || self.probes != session.probes ||
        self.dataRecords != session.dataRecords || self.zeroRecords != session.zeroRecords ||
        self.report.runtimeErrors != session.runtimeErrors || self.report.drops != session.drops)
        self.Fail(DecodeIssueKind::Transport, "session incomplete or delivered batch/counter mismatch");
    if (!self.report.startNs || !self.report.endNs)
        self.Fail(DecodeIssueKind::Clock, "missing DTrace session boundary");
    self.CheckClock();
    DecodedBatch output;
    self.Flush(output);
    for (auto& item : self.pending)
    {
        auto& event = item.second;
        if (event.entryPresent && self.report.startNs && event.rawEntryNs &&
            *event.rawEntryNs >= *self.report.startNs &&
            (!self.report.endNs || *event.rawEntryNs <= *self.report.endNs))
            event.timestampNs = *event.rawEntryNs - *self.report.startNs;
        event.state = !self.report.issue && event.entryPresent && cancellationRequested ?
            NativeEventState::Cancelled : NativeEventState::Incomplete;
        self.Add(event.state == NativeEventState::Cancelled ? self.report.cancelled : self.report.incomplete, 1);
        output.events.push_back(std::move(event));
    }
    self.pending.clear();
    self.report.finalized = true;
    self.report.complete = !self.report.issue && !cancellationRequested &&
        self.report.incomplete == 0 && self.report.runtimeErrors == 0 && self.report.drops == 0;
    output.issue = self.report.issue;
    return output;
}

const DecoderReport& NativeEventDecoder::Report() const noexcept { return impl->report; }

} // namespace procmon::freebsd
