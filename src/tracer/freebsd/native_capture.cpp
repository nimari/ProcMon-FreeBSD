// SPDX-License-Identifier: MIT
#include "native_capture.h"

#if !defined(__FreeBSD__) || !defined(__amd64__)
#error "Native capture currently targets FreeBSD amd64 only"
#endif
#include <unistd.h>

#include <stdexcept>
#include <utility>

namespace procmon::freebsd
{

struct NativeCapture::Impl
{
    DTraceSession session;
    std::unique_ptr<NativeEventDecoder> decoder;
    CapturePhase phase = CapturePhase::Ready;
    CaptureEndReason reason = CaptureEndReason::None;
    std::uint64_t targetPid = 0, monitorPid = 0;
    bool failed = false, stopRequested = false, cancellationRequested = false;
    std::string diagnostic;

    ~Impl() { Close(); }
    bool Terminal() const { return phase == CapturePhase::Finished || phase == CapturePhase::Closed; }
    void Fail(const std::string& message)
    {
        failed = true; reason = CaptureEndReason::Failure;
        if (diagnostic.empty()) diagnostic = message;
        if (phase == CapturePhase::Running)
        {
            phase = CapturePhase::Stopping;
            stopRequested = true;
        }
    }
    static void Append(CaptureUpdate& update, DecodedBatch&& batch)
    {
        for (auto& event : batch.events) update.events.push_back(std::move(event));
    }
    void Finish(CaptureUpdate& update)
    {
        session.Close();
        if (decoder && !decoder->Report().finalized)
        {
            auto final = decoder->Finish(session.Status(), cancellationRequested);
            if (final.issue) Fail(final.issue->message);
            Append(update, std::move(final));
        }
        if (!decoder || !decoder->Report().finalized || session.Status().failed ||
            session.Status().discarded || !session.Status().drained)
            Fail("capture could not be finalized completely");
        if (decoder && !decoder->Report().complete && !cancellationRequested && !failed)
            Fail("capture has unresolved observations or data loss");
        reason = failed ? CaptureEndReason::Failure : cancellationRequested ?
            CaptureEndReason::Cancelled : CaptureEndReason::Completed;
        phase = CapturePhase::Finished;
        update.finished = true;
    }
    void Close() noexcept
    {
        session.Close();
        if (session.Status().failed) failed = true;
        if (!Terminal())
        {
            phase = CapturePhase::Closed;
            reason = failed ? CaptureEndReason::Failure : CaptureEndReason::Abandoned;
        }
    }
};

NativeCapture::NativeCapture() : impl(std::make_unique<Impl>()) {}
NativeCapture::~NativeCapture() = default;

bool NativeCapture::Start(const CaptureConfiguration& configuration)
{
    auto& self = *impl;
    if (self.phase != CapturePhase::Ready)
        throw std::logic_error("capture controller is single-use");
    self.targetPid = configuration.targetPid;
    self.monitorPid = static_cast<std::uint64_t>(getpid());
    try
    {
        auto program = BuildNativeProgram({configuration.targetPid, self.monitorPid, configuration.operations, configuration.identity});
        self.decoder = std::make_unique<NativeEventDecoder>(configuration.targetPid,
            configuration.maximumPending, configuration.recentCompletedKeys);
        if (!self.session.Start(program.source, {}, configuration.transport))
        {
            self.Fail(self.session.Status().diagnostic);
            CaptureUpdate unused;
            self.Finish(unused);
            return false;
        }
        self.phase = CapturePhase::Running;
        return true;
    }
    catch (const std::invalid_argument& error)
    {
        self.Fail(error.what());
        CaptureUpdate unused;
        self.Finish(unused);
        return false;
    }
    catch (...)
    {
        self.failed = true; self.reason = CaptureEndReason::Failure;
        self.Close();
        throw;
    }
}

void NativeCapture::RequestStop(CaptureEndReason reason)
{
    auto& self = *impl;
    if (reason != CaptureEndReason::Completed && reason != CaptureEndReason::Cancelled)
        throw std::invalid_argument("stop reason must be Completed or Cancelled");
    if (self.phase == CapturePhase::Finished) return;
    if (self.phase != CapturePhase::Running && self.phase != CapturePhase::Stopping)
        throw std::logic_error("capture is not running");
    self.stopRequested = true;
    self.cancellationRequested = self.cancellationRequested || reason == CaptureEndReason::Cancelled;
    self.phase = CapturePhase::Stopping;
}

CaptureUpdate NativeCapture::Poll()
{
    auto& self = *impl;
    if (self.phase == CapturePhase::Ready) throw std::logic_error("capture has not started");
    CaptureUpdate update;
    if (self.Terminal()) { update.finished = true; return update; }
    try
    {
        if (self.phase == CapturePhase::Stopping && !self.session.Status().stopped)
        {
            if (!self.session.Stop())
            {
                self.Fail(self.session.Status().diagnostic);
                self.Finish(update);
                return update;
            }
        }
        auto batch = self.session.Poll();
        if (batch.outcome == PollOutcome::Error)
            self.Fail(self.session.Status().diagnostic.empty() ? "session polling failed" : self.session.Status().diagnostic);
        auto decoded = self.decoder->Consume(batch);
        if (decoded.issue) self.Fail(decoded.issue->message);
        Impl::Append(update, std::move(decoded));
        update.notices = std::move(batch.notices);
        if (self.session.Status().runtimeErrors) self.Fail("DTrace runtime error reported");
        if (self.session.Status().drops) self.Fail("DTrace dropped capture data");
        if (batch.outcome == PollOutcome::Error)
        {
            self.Finish(update);
        }
        else if (batch.outcome == PollOutcome::Done)
        {
            if (self.phase == CapturePhase::Running)
                self.Fail("capture ended without a stop request");
            self.Finish(update);
        }
        return update;
    }
    catch (...)
    {
        self.failed = true; self.reason = CaptureEndReason::Failure;
        self.Close();
        throw;
    }
}

void NativeCapture::Close() noexcept { impl->Close(); }

CaptureReport NativeCapture::Report() const
{
    const auto& self = *impl;
    CaptureReport report;
    report.phase = self.phase; report.reason = self.reason;
    report.targetPid = self.targetPid; report.monitorPid = self.monitorPid;
    report.stopRequested = self.stopRequested; report.cancellationRequested = self.cancellationRequested;
    report.session = self.session.Status();
    if (self.decoder) report.decoder = self.decoder->Report();
    report.diagnostic = self.diagnostic;
    report.complete = self.phase == CapturePhase::Finished && self.reason == CaptureEndReason::Completed &&
        report.decoder && report.decoder->complete && !report.session.failed && !report.session.discarded;
    return report;
}

} // namespace procmon::freebsd
