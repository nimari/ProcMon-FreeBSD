// SPDX-License-Identifier: MIT
// Standalone diagnostic pilot, deliberately outside the ProcMon application CLI.
#include "support.h"
#include "target_watch.h"
#include <signal.h>
#include <chrono>
#include <iostream>
#include <thread>

namespace d = procmon::freebsd::diagnostic;
using namespace procmon::freebsd;
static volatile sig_atomic_t caughtSignal;
static void Catch(int value) { if (!caughtSignal) caughtSignal = value; }
static void Signals()
{
    struct sigaction action{};
    sigemptyset(&action.sa_mask);
    sigaddset(&action.sa_mask, SIGINT);
    sigaddset(&action.sa_mask, SIGTERM);
    action.sa_handler = Catch;
    // Restart interrupted system calls where supported. Handler only sets a flag.
    action.sa_flags = SA_RESTART;
    if (sigaction(SIGINT, &action, nullptr) || sigaction(SIGTERM, &action, nullptr))
        throw std::runtime_error("cannot install stop handlers");
    action.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &action, nullptr)) throw std::runtime_error("cannot ignore SIGPIPE");
}
static void Flush()
{
    std::cout.flush();
    if (!std::cout) throw std::runtime_error("capture output failed; unfinished capture abandoned");
}
int main(int argc, char** argv)
{
    d::Options options;
    try { options = d::Parse(argc, argv); }
    catch (const std::invalid_argument& error)
    { std::cerr << "procmon-freebsd-capture: " << error.what() << "; use --help\n"; return 2; }
    if (options.help)
    {
        std::cout << "FreeBSD amd64 headless diagnostic pilot (not the ProcMon application)\n"
            "Usage: procmon-freebsd-capture --pid PID [--events openat,read,write] [--duration-ms MS]\n"
            "One native PID is required; all three operations are selected by default.\n"
            "Duration: 1..86400000 ms after tracing starts; otherwise wait for SIGINT/SIGTERM.\n"
            "JSON Lines v1; strings encode bytes as code points 0..255. Events are provisional\n"
            "until the final summary. Paths: up to 64 bytes; read/write buffers are not captured.\n"
            "Requires a live native FreeBSD ELF64 target. PID reuse is excluded by an identity guard.\n"
            "Target exit stops capture; later exec ends it as failure. No child following.\n"
            "Needs an available DTrace syscall provider and tracing privileges. Loads no modules.\n"
            "Exit: 0 complete duration/target-exit stop, 1 failure, 2 usage, 130 SIGINT, 143 SIGTERM.\n"
            "Signals stop/drain/close capture and leave the target running.\n";
        return std::cout ? 0 : 1;
    }
    try
    {
        Signals();
        NativeCapture capture;
        d::TargetWatch watch;
        d::TargetStatus target;
        try { watch.Arm(options.capture.targetPid); }
        catch (const std::runtime_error& error)
        {
            auto report = capture.Report();
            report.targetPid = options.capture.targetPid; report.monitorPid = getpid();
            report.reason = CaptureEndReason::Failure; report.diagnostic = error.what();
            target.stopCause = "preflight";
            d::Summary(std::cout, report, caughtSignal, &target); Flush();
            std::cerr << "procmon-freebsd-capture: " << error.what() << '\n'; return 1;
        }
        target.validated = true;
        target.startSeconds = watch.identity.startSeconds;
        target.startMicroseconds = watch.identity.startMicroseconds;
        options.capture.identity = watch.identity;
        if (!capture.Start(options.capture))
        {
            const auto report = capture.Report();
            target.stopCause = "capture_start";
            d::Summary(std::cout, report, caughtSignal, &target); Flush();
            std::cerr << "procmon-freebsd-capture: " << report.diagnostic << '\n';
            return 1;
        }
        const auto start = std::chrono::steady_clock::now();
        bool requested = false, watching = true;
        std::string policyFailure;
        auto observe = [&](bool startup)
        {
            if (!watching) return;
            try
            {
                const auto change = watch.Poll();
                if (change == d::TargetChange::None) return;
                target.exitStatus = watch.exitStatus;
                if (target.stopCause.empty() || change == d::TargetChange::Exec)
                    target.stopCause = change == d::TargetChange::Exec ? "exec" : "exit";
                if (startup) policyFailure = "target: process changed during capture startup";
                else if (change == d::TargetChange::Exec) policyFailure = "target: exec ended the validated image; capture stopped";
            }
            catch (const std::runtime_error& error)
            { policyFailure = error.what(); target.stopCause = "watch_error"; }
            watching = false;
            capture.RequestStop(CaptureEndReason::Completed); requested = true;
        };
        observe(true);
        const bool ready = policyFailure.empty();
        if (ready) { d::Ready(std::cout, capture.Report(), options, &target); Flush(); }
        for (;;)
        {
            observe(false);
            if (caughtSignal)
            {
                // Allow a signal to upgrade an already requested duration stop.
                capture.RequestStop(CaptureEndReason::Cancelled);
                if (policyFailure.empty()) target.stopCause = "signal";
                requested = true;
            }
            else if (!requested && options.durationMs && std::chrono::steady_clock::now() - start >=
                std::chrono::milliseconds(options.durationMs))
            { capture.RequestStop(CaptureEndReason::Completed); requested = true; target.stopCause = "duration"; }
            auto update = capture.Poll();
            if (ready)
            {
                for (const auto& event : update.events) d::Event(std::cout, event);
                for (const auto& notice : update.notices) d::Notice(std::cout, notice);
            }
            Flush();
            if (update.finished) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        // Check an exec/exit queued during the final drainage as well.
        observe(false);
        auto report = capture.Report();
        if (!policyFailure.empty())
        { report.reason = CaptureEndReason::Failure; report.complete = false;
          if (report.diagnostic.empty()) report.diagnostic = policyFailure; }
        else if (report.reason == CaptureEndReason::Failure) target.stopCause = "capture_failure";
        d::Summary(std::cout, report, caughtSignal, &target); Flush();
        if (report.reason == CaptureEndReason::Failure)
        { std::cerr << "procmon-freebsd-capture: " << report.diagnostic << '\n'; return 1; }
        if (report.reason == CaptureEndReason::Cancelled && caughtSignal) return 128 + caughtSignal;
        return report.complete ? 0 : 1;
    }
    catch (const std::exception& error)
    { std::cerr << "procmon-freebsd-capture: " << error.what() << '\n'; return 1; }
}
