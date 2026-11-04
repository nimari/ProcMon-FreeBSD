// SPDX-License-Identifier: MIT
#include "../../src/tracer/freebsd/native_capture.h"
#include <unistd.h>
#include <iostream>
#include <stdexcept>

using namespace procmon::freebsd;
static unsigned int checks;
static void Check(bool value)
{ ++checks; if (!value) throw std::runtime_error("controller check " + std::to_string(checks) + " failed"); }
template<class Exception, class Function> static void Throws(Function function)
{
    bool caught = false;
    try { function(); } catch (const Exception&) { caught = true; }
    Check(caught);
}
int main()
{
    try
    {
        NativeCapture unused;
        Check(unused.Report().phase == CapturePhase::Ready && !unused.Report().session.opened);
        Throws<std::logic_error>([&] { unused.Poll(); });
        Throws<std::logic_error>([&] { unused.RequestStop(CaptureEndReason::Completed); });
        Throws<std::invalid_argument>([&] { unused.RequestStop(CaptureEndReason::None); });
        unused.Close(); unused.Close();
        Check(unused.Report().phase == CapturePhase::Closed && unused.Report().reason == CaptureEndReason::Abandoned &&
            !unused.Report().complete && unused.Poll().finished);
        for (int item = 0; item < 7; ++item)
        {
            CaptureConfiguration config;
            config.targetPid = static_cast<std::uint64_t>(getpid()); config.operations = {NativeOperation::Read};
            if (item == 0) config.targetPid = 0;
            if (item == 1) config.targetPid = UINT64_MAX;
            if (item == 2) config.operations.clear();
            if (item == 3) config.operations = {static_cast<NativeOperation>(99)};
            if (item == 4) config.maximumPending = 0;
            if (item == 5) config.recentCompletedKeys = 0;
            if (item == 6) config.transport.maximumBatchBytes = 0;
            NativeCapture capture;
            Check(!capture.Start(config));
            auto report = capture.Report();
            Check(report.phase == CapturePhase::Finished && report.reason == CaptureEndReason::Failure &&
                !report.complete && !report.diagnostic.empty() && report.monitorPid == static_cast<std::uint64_t>(getpid()) &&
                report.session.closed && !report.session.opened && !report.session.started);
            Check(capture.Poll().finished && capture.Poll().events.empty());
            Throws<std::logic_error>([&] { capture.Start(config); });
            capture.RequestStop(CaptureEndReason::Cancelled); capture.Close();
            Check(capture.Report().reason == CaptureEndReason::Failure && !capture.Report().cancellationRequested);
        }
        std::cout << "PASS: " << checks << " capture-controller lifecycle/configuration checks\n";
        return 0;
    }
    catch (const std::exception& error) { std::cerr << "FAIL: " << error.what() << '\n'; return 1; }
}
