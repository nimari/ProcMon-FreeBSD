// SPDX-License-Identifier: MIT
#include "engine.h"
#include "storage.h"
#include "symbols.h"
#include "../diagnostic/target_watch.h"
#include <pthread.h>
#include <chrono>
#include <future>
#include <mutex>
#include <sstream>

namespace procmon::freebsd::app
{
volatile sig_atomic_t stopSignal;
std::atomic<bool> applicationFinished{false}, applicationFailed{false};
std::uint64_t durationMilliseconds = 0;
bool captureStrings = true, captureBuffers = true, captureStacks = true;
namespace { std::mutex statusMutex; std::string status = "initializing"; }
std::string CaptureStatus() { std::lock_guard<std::mutex> lock(statusMutex); return status; }
void SetCaptureStatus(const std::string& value) { std::lock_guard<std::mutex> lock(statusMutex); status = value; }
NativeEngine::NativeEngine(std::shared_ptr<IStorageEngine> storage, std::vector<Event> events,
    std::vector<pid_t> pids, std::vector<SyscallSchema> schemas): ITracerEngine(storage,std::move(events)),pids(std::move(pids)),schemas(std::move(schemas)) {}
NativeEngine::~NativeEngine() { Cancel(); }
void NativeEngine::Initialize()
{
    if (worker.joinable()) throw std::runtime_error("native application tracer is single-use");
    auto* storage = dynamic_cast<NativeStorage*>(_storageEngine.get());
    if (!storage) throw std::runtime_error("native application tracer requires FreeBSD storage");
    auto initialized = std::make_shared<std::promise<void>>(); auto ready = initialized->get_future();
    state = TRACER_RUNNING; applicationFinished = false; applicationFailed = false;
    worker = std::thread([this,storage,initialized]
    {
        bool notified = false;
        std::uint64_t errors = 0, drops = 0, unresolved = 0, extras = 0, pauses = 0;
        bool cancelled = false;
        std::string reason = "completed";
        try
        {
            sigset_t blocked; sigemptyset(&blocked); sigaddset(&blocked,SIGINT); sigaddset(&blocked,SIGTERM);
            pthread_sigmask(SIG_BLOCK,&blocked,nullptr);
            struct Watched { std::uint64_t pid; std::unique_ptr<diagnostic::TargetWatch> watch; bool exited = false; };
            std::vector<Watched> watched;
            CaptureOptions options; options.strings = captureStrings; options.buffers = captureBuffers; options.stacks = captureStacks;
            options.allSyscalls = _targetEvents.empty();
            storage->Metadata("strings",captureStrings ? "true" : "false");
            storage->Metadata("buffers",captureBuffers ? "true" : "false");
            storage->Metadata("stacks",captureStacks ? "true" : "false");
            for (const auto& schema : schemas)
                if (_targetEvents.empty() || std::any_of(_targetEvents.begin(),_targetEvents.end(),[&](const auto& event) { return event.Name() == schema.syscallName; })) options.schemas.push_back(schema);
            NativeSymbols symbols;
            for (auto pid : pids)
            {
                auto watch = std::make_unique<diagnostic::TargetWatch>(); watch->Arm(pid);
                options.targets.push_back({static_cast<std::uint64_t>(pid),watch->identity});
                if (captureStacks) symbols.Prime(pid);
                storage->Metadata("target_" + std::to_string(pid) + "_abi","FreeBSD ELF64");
                watched.push_back({static_cast<std::uint64_t>(pid),std::move(watch),false});
            }
            bool policyFailed = false; std::string policyDiagnostic;
            auto targetsExited = [&]
            {
                bool all = !watched.empty();
                for (auto& target : watched)
                {
                    if (!target.exited)
                    {
                        try
                        {
                            const auto change = target.watch->Poll();
                            if (change == diagnostic::TargetChange::Exec)
                            { policyFailed = true; policyDiagnostic = "selected target executed a new image; identity-scoped capture stopped"; }
                            if (change == diagnostic::TargetChange::Exit)
                            { target.exited = true; storage->Metadata("target_" + std::to_string(target.pid) + "_exit_status",std::to_string(target.watch->exitStatus.value_or(0))); }
                        }
                        catch (const std::exception& error) { policyFailed = true; policyDiagnostic = error.what(); }
                    }
                    all &= target.exited;
                }
                return all;
            };
            auto wallStart = std::chrono::steady_clock::now(); bool firstSegment = true;
            std::optional<std::uint64_t> origin;
            bool finished = false;
            while (!finished)
            {
                if (targetsExited()) { reason = "target-exit"; break; }
                if (policyFailed) { reason = "target-change"; break; }
                if (state == TRACER_STOP) { cancelled = true; reason = "cancelled"; break; }
                if (durationMilliseconds && std::chrono::steady_clock::now() - wallStart >= std::chrono::milliseconds(durationMilliseconds)) { reason = "duration"; break; }
                if (state == TRACER_SUSPENDED) { std::this_thread::sleep_for(std::chrono::milliseconds(10)); continue; }
                ApplicationCapture capture(options,origin); capture.Start();
                if (firstSegment) { wallStart = std::chrono::steady_clock::now(); firstSegment = false; }
                storage->Metadata("status","capturing");
                bool stopping = false, paused = false;
                while (!capture.Quality().done)
                {
                    const bool exited = targetsExited();
                    const bool timed = durationMilliseconds && std::chrono::steady_clock::now() - wallStart >= std::chrono::milliseconds(durationMilliseconds);
                    if (!stopping && (state != TRACER_RUNNING || exited || timed || policyFailed))
                    {
                        paused = state == TRACER_SUSPENDED;
                        const bool cancel = state != TRACER_RUNNING && !policyFailed;
                        capture.Stop(cancel); stopping = true;
                        if (paused) { ++pauses; reason = "paused"; }
                        else { finished = true; cancelled = cancel; reason = policyFailed ? "target-change" : exited ? "target-exit" : timed ? "duration" : "cancelled"; }
                    }
                    auto events = capture.Poll();
                    if (!origin && capture.Quality().start)
                    {
                        origin = capture.Quality().start;
                        storage->Metadata("raw_origin_ns",std::to_string(*origin));
                        storage->Metadata("syscall_count",std::to_string(options.schemas.size()));
                        if (targetsExited()) { policyFailed = true; policyDiagnostic = "target changed during application capture startup"; }
                        if (policyFailed)
                        { if (!stopping) { capture.Stop(false); stopping = true; } finished = true; reason = "startup-change"; }
                        else
                        {
                        initialized->set_value(); notified = true;
                        }
                    }
                    std::vector<ITelemetry> telemetry; telemetry.reserve(events.size());
                    for (auto& event : events) { if (captureStacks) symbols.Resolve(event); telemetry.push_back(Telemetry(event.data)); }
                    if (!telemetry.empty()) storage->StoreMany(std::move(telemetry));
                    SetCaptureStatus(stopping ? reason : "capturing; faults=" + std::to_string(errors + capture.Quality().runtimeErrors) + " drops=" + std::to_string(drops + capture.Quality().drops));
                    if (!capture.Quality().done) std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
                errors += capture.Quality().runtimeErrors; drops += capture.Quality().drops;
                unresolved += capture.Quality().unresolved; extras += capture.Quality().missingExtras;
                if (capture.Quality().end) storage->Metadata("raw_end_ns",std::to_string(*capture.Quality().end));
                if (paused) { storage->Metadata("pauses",std::to_string(pauses)); storage->Metadata("status","paused");
                    storage->Metadata("complete","false"); SetCaptureStatus("paused; unobserved interval"); }
            }
            const bool incomplete = errors || drops || unresolved || extras || policyFailed;
            applicationFailed = incomplete;
            storage->Metadata("runtime_errors",std::to_string(errors)); storage->Metadata("drops",std::to_string(drops));
            storage->Metadata("unresolved",std::to_string(unresolved)); storage->Metadata("missing_snapshots",std::to_string(extras));
            storage->Metadata("pauses",std::to_string(pauses)); storage->Metadata("stop_reason",reason);
            storage->Metadata("complete",incomplete || cancelled || pauses ? "false" : "true");
            storage->Metadata("status",incomplete ? "incomplete" : reason);
            if (policyFailed) storage->Metadata("diagnostic",policyDiagnostic);
            SetCaptureStatus((incomplete ? "incomplete: " : "stopped: ") + reason + "; faults=" + std::to_string(errors) + " drops=" + std::to_string(drops));
            if (!notified) throw std::runtime_error(policyDiagnostic.empty() ? "application capture ended before readiness" : policyDiagnostic);
        }
        catch (...)
        {
            applicationFailed = true;
            std::string diagnostic = "native capture failed";
            try { throw; } catch (const std::exception& error) { diagnostic = error.what(); } catch (...) {}
            SetCaptureStatus("failed: " + diagnostic);
            try { storage->Metadata("status","failed"); storage->Metadata("complete","false"); storage->Metadata("diagnostic",diagnostic); } catch (...) {}
            if (!notified) initialized->set_exception(std::current_exception());
        }
        state = TRACER_STOP; applicationFinished = true;
    });
    while (ready.wait_for(std::chrono::milliseconds(20)) != std::future_status::ready)
        if (stopSignal) state = TRACER_STOP;
    ready.get();
}
void NativeEngine::SetRunState(int value)
{
    if (value != TRACER_RUNNING && value != TRACER_SUSPENDED && value != TRACER_STOP) throw std::runtime_error("invalid native tracer run state");
    if (applicationFinished && value != TRACER_STOP) return;
    state = value;
    if (value == TRACER_STOP && worker.joinable()) worker.join();
}
void NativeEngine::Cancel() { SetRunState(TRACER_STOP); }
} // namespace procmon::freebsd::app
