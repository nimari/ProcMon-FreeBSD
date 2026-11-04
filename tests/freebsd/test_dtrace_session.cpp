// SPDX-License-Identifier: MIT
// Fixture/process policy belongs here, not in the reusable session component.
#include "../../src/tracer/freebsd/dtrace_session.h"
#ifdef PROCMON_TEST_NATIVE_DECODER
#include "../../src/tracer/freebsd/native_event_decoder.h"
static bool decodeEvents;
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dtrace.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

using namespace procmon::freebsd;
using Clock = std::chrono::steady_clock;
static unsigned int opened, closed, stopped;
static volatile sig_atomic_t interrupted;

extern "C"
{
dtrace_hdl_t* __real_dtrace_open(int, int, int*);
void __real_dtrace_close(dtrace_hdl_t*);
int __real_dtrace_stop(dtrace_hdl_t*);
dtrace_hdl_t* __wrap_dtrace_open(int version, int flags, int* error)
{
    auto* handle = __real_dtrace_open(version, flags, error);
    opened += handle != nullptr;
    return handle;
}
void __wrap_dtrace_close(dtrace_hdl_t* handle) { ++closed; __real_dtrace_close(handle); }
int __wrap_dtrace_stop(dtrace_hdl_t* handle) { ++stopped; return __real_dtrace_stop(handle); }
}

static void Signal(int number) { interrupted = number; }
static void Require(bool value, const char* message)
{
    if (!value) throw std::runtime_error(message);
}

struct Child
{
    pid_t pid = -1;
    int gate = -1, status = -1;
    bool reaped = false;

    Child(const std::string& fixture, const std::string& directory,
        const std::string& uid, const std::string& gid, const std::string& mode)
    {
        int pipefd[2];
        Require(pipe(pipefd) == 0, "pipe failed");
        pid = fork();
        if (pid < 0) { close(pipefd[0]); close(pipefd[1]); throw std::runtime_error("fork failed"); }
        if (pid == 0)
        {
            close(pipefd[1]);
            alarm(12);
            char token;
            if (setgroups(0, nullptr) || setgid(static_cast<gid_t>(std::stoul(gid))) ||
                setuid(static_cast<uid_t>(std::stoul(uid))) || read(pipefd[0], &token, 1) != 1)
                _exit(125);
            close(pipefd[0]);
            int output = open((directory + "/fixture.tsv").c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
            if (output < 0 || dup2(output, STDOUT_FILENO) < 0) _exit(125);
            close(output);
            if (mode == "sigint" || mode == "sigterm")
                execl(fixture.c_str(), fixture.c_str(), directory.c_str(), uid.c_str(), gid.c_str(),
                    mode.c_str(), static_cast<char*>(nullptr));
            else
                execl(fixture.c_str(), fixture.c_str(), directory.c_str(), uid.c_str(), gid.c_str(),
                    static_cast<char*>(nullptr));
            _exit(126);
        }
        close(pipefd[0]);
        gate = pipefd[1];
    }
    void Reap(bool wait)
    {
        if (reaped) return;
        int value;
        pid_t outcome;
        do { outcome = waitpid(pid, &value, wait ? 0 : WNOHANG); } while (outcome < 0 && errno == EINTR);
        Require(outcome >= 0, "waitpid failed");
        if (outcome == pid)
        {
            reaped = true;
            status = WIFEXITED(value) ? WEXITSTATUS(value) : 128 + WTERMSIG(value);
        }
    }
    void Release()
    {
        Require(write(gate, "x", 1) == 1, "fixture release failed");
        close(gate); gate = -1;
    }
    void Cleanup()
    {
        if (gate >= 0) { close(gate); gate = -1; }
        if (!reaped) { kill(pid, SIGKILL); Reap(true); }
    }
    ~Child() { try { Cleanup(); } catch (...) {} }
};

static std::vector<std::uint64_t> Values(const CapturedProbe& probe, std::string& path)
{
    std::vector<std::uint64_t> values;
    for (const auto& record : probe.records)
    {
        Require(record.action == DTRACEACT_DIFEXPR, "unexpected action in fixture decoder");
        if (record.bytes.empty()) continue;
        if (record.bytes.size() == 8)
        {
            std::uint64_t value;
            std::memcpy(&value, record.bytes.data(), sizeof(value));
            values.push_back(value);
        }
        else
        {
            Require(record.bytes.size() == 65 && path.empty() &&
                std::memchr(record.bytes.data(), 0, 65), "invalid fixture path field");
            path = reinterpret_cast<const char*>(record.bytes.data());
        }
    }
    return values;
}

static std::int64_t Signed(std::uint64_t bits)
{
    std::int64_t value;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}

static std::string Render(const std::vector<SessionBatch>& batches, pid_t pid, bool signalCase)
{
    std::ostringstream out;
    for (const auto& batch : batches)
    {
        for (const auto& notice : batch.notices)
            std::cerr << (notice.kind == NoticeKind::Drop ? "SESSION_DROP\t" : "SESSION_ERROR\t")
                      << notice.detail << '\t' << notice.count << '\t' << notice.message;
        for (const auto& probe : batch.probes)
        {
            std::string path;
            auto value = Values(probe, path);
            Require(!value.empty() && value[0] == static_cast<std::uint64_t>(pid), "wrong captured PID");
            if (probe.provider == "dtrace")
            {
                Require(value.size() == 1 && (probe.name == "BEGIN" || probe.name == "END"), "lifecycle schema");
                out << probe.name;
                if (probe.name == "BEGIN") out << '\t' << pid;
                out << '\n';
                continue;
            }
            Require(probe.provider == "syscall" && probe.module == "freebsd", "wrong ABI/provider");
            if (probe.function == "getpgid")
            {
                Require(value.size() == 3 && (value[2] == 0 || value[2] == value[0]), "marker schema");
                out << (value[2] ? "STOP" : "START") << '\t' << pid << '\t' << value[1] << '\n';
            }
            else if (probe.function == "_exit")
            {
                Require(value.size() == 2, "exit schema");
                out << "TARGET_EXIT\t" << pid << '\t' << value[1] << '\n';
            }
            else if (signalCase)
            {
                Require(probe.function == "read" && value.size() == 5, "signal schema");
                out << (probe.name == "entry" ? "BLOCKED" : "BLOCK_RETURN");
                for (auto item : value) out << '\t' << item;
                out << '\n';
            }
            else
            {
                bool entry = probe.name == "entry";
                Require((entry || probe.name == "return") && value.size() == (entry ? 5U : 8U) &&
                    !path.empty(), "syscall schema");
                out << (entry ? "ENTRY" : "EVENT") << '\t' << pid << '\t' << value[1]
                    << '\t' << probe.function << '\t' << value[2] << '\t';
                if (entry)
                    out << Signed(value[3]) << '\t' << value[4];
                else
                    out << value[3] << '\t' << Signed(value[4]) << '\t' << value[5]
                        << '\t' << Signed(value[6]) << '\t' << value[7];
                out << '\t' << path << '\n';
            }
        }
    }
    return out.str();
}

#ifdef PROCMON_TEST_NATIVE_DECODER
static const char* Operation(NativeOperation operation)
{
    return operation == NativeOperation::OpenAt ? "openat" : operation == NativeOperation::Read ? "read" : "write";
}
static void RenderDecoder(const std::vector<SessionBatch>& batches, pid_t pid,
    const std::vector<NativeEvent>& events, const DecoderReport& report, std::size_t streamed)
{
    for (const auto& batch : batches)
        for (const auto& probe : batch.probes)
        {
            std::string path;
            auto value = Values(probe, path);
            Require(!value.empty() && value[0] == static_cast<std::uint64_t>(pid), "decoder raw PID");
            if (probe.provider == "dtrace")
            {
                Require(value.size() == 2, "decoder raw session boundary");
                std::cout << "RAW_BOUNDARY\t" << probe.name << '\t' << pid << '\t' << value[1] << '\n';
                std::cout << probe.name << (probe.name == "BEGIN" ? "\t" + std::to_string(pid) : "") << '\n';
            }
            else if (probe.function == "getpgid")
                std::cout << (value[2] ? "STOP" : "START") << '\t' << pid << '\t' << value[1] << '\n';
            else if (probe.function == "_exit")
                std::cout << "TARGET_EXIT\t" << pid << '\t' << value[1] << '\n';
            else
            {
                bool entry = probe.name == "entry";
                std::cout << (entry ? "RAW_ENTRY" : "RAW_RETURN") << '\t' << pid << '\t' << value[1]
                          << '\t' << probe.function << '\t' << value[2] << '\t';
                if (entry) std::cout << Signed(value[3]) << '\t' << value[4];
                else std::cout << value[3] << '\t' << Signed(value[4]) << '\t' << value[5]
                               << '\t' << Signed(value[6]) << '\t' << value[7];
                std::cout << '\t' << path << '\n';
            }
        }
    std::cout << "SESSION\t1\tfreebsd-native\tdtrace-session-ns\t" << pid << '\t'
              << report.startNs.value_or(0) << '\t' << report.endNs.value_or(0) << '\n';
    for (const auto& event : events)
    {
        const char* state = event.state == NativeEventState::Completed ? "completed" :
            event.state == NativeEventState::Cancelled ? "cancelled" : "incomplete";
        std::cout << "CONTRACT_EVENT\t" << event.version << '\t' << event.pid << '\t' << event.tid
                  << '\t' << Operation(event.operation) << '\t' << state
                  << '\t' << event.timestampNs.has_value() << '\t' << event.timestampNs.value_or(0)
                  << '\t' << event.durationNs.has_value() << '\t' << event.durationNs.value_or(0)
                  << '\t' << event.result.has_value() << '\t' << event.result.value_or(0)
                  << '\t' << event.error.has_value() << '\t' << event.error.value_or(0)
                  << '\t' << event.entryPresent << '\t' << event.returnPresent
                  << '\t' << (event.returned ? event.returned->result : 0)
                  << '\t' << (event.returned ? event.returned->errnoBits : 0) << '\n';
        std::cout << "NATIVE_ARGUMENTS\t" << event.pid << '\t' << event.tid << '\t' << Operation(event.operation)
                  << '\t' << event.correlationStartNs << '\t' << event.arguments.descriptor
                  << '\t' << event.arguments.third << '\t' << event.arguments.path.has_value()
                  << '\t' << (event.arguments.path && event.arguments.path->atCaptureLimit)
                  << '\t' << (event.arguments.path ? event.arguments.path->text : "-") << '\n';
    }
    std::cout << "CONTRACT_COUNTS\t" << report.completed << '\t' << report.cancelled << '\t' << report.incomplete << '\n'
              << "DECODER_REPORT\tcomplete=" << report.complete << "\tissue="
              << (report.issue ? static_cast<int>(report.issue->kind) : -1)
              << "\tstreamed=" << streamed << "\terrors=" << report.runtimeErrors << "\tdrops=" << report.drops << '\n';
}
#endif

static void Run(const std::string& program, const std::string& fixture, const std::string& directory,
    const std::string& uid, const std::string& gid, const std::string& mode, int round)
{
    Child child(fixture, directory, uid, gid, mode); // Fork before opening libdtrace.
    std::vector<SessionBatch> batches;
#ifdef PROCMON_TEST_NATIVE_DECODER
    std::unique_ptr<NativeEventDecoder> decoder;
    std::vector<NativeEvent> typed;
    if (decodeEvents) decoder = std::make_unique<NativeEventDecoder>(child.pid);
#endif
    DTraceSession session;
    SessionOptions options;
    if (mode == "drop") options.bufferSize = "1k";
    if (mode == "limit") options.maximumBatchBytes = 1;
    int macro = mode == "fault" ? 1 : mode == "drop" ? 2 : mode == "sigint" ? 4 : mode == "sigterm" ? 5 : 0;
#ifdef PROCMON_TEST_NATIVE_DECODER
    if (decodeEvents && mode == "drop") macro = 0;
#endif
    bool started = session.Start(mode == "startup" ? "this is not valid D source;" : program,
        {std::to_string(child.pid), std::to_string(macro)}, options);
    auto deadline = Clock::now() + std::chrono::seconds(10);
    Clock::time_point cancelStart{};
    bool blocked = false;
    if (started && mode != "abandon") child.Release();
    if (mode == "abandon") session.Close();
    while (started && mode != "abandon")
    {
        Require(Clock::now() < deadline, "capture watchdog expired");
        child.Reap(false);
        if (interrupted || child.reaped || session.Status().runtimeErrors || session.Status().drops)
        {
            child.Cleanup(); // Only the harness-owned fixture, never arbitrary targets.
            session.Stop();
        }
        if (mode != "drop" || child.reaped)
        {
            auto batch = session.Poll();
#ifdef PROCMON_TEST_NATIVE_DECODER
            if (decoder)
            {
                auto decoded = decoder->Consume(batch);
                Require(!decoded.issue || mode == "drop", "native decoder consume failed");
                for (auto& event : decoded.events) typed.push_back(std::move(event));
            }
#endif
            for (const auto& probe : batch.probes)
                if (probe.provider == "syscall" && probe.module == "freebsd" &&
                    probe.function == "read" && probe.name == "entry") blocked = true;
            auto outcome = batch.outcome;
            batches.push_back(std::move(batch));
            if (outcome == PollOutcome::Done || outcome == PollOutcome::Error) break;
        }
        if ((mode == "sigint" || mode == "sigterm") && blocked && !interrupted)
        {
            cancelStart = Clock::now();
            Require(kill(getpid(), mode == "sigint" ? SIGINT : SIGTERM) == 0, "signal delivery failed");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    child.Cleanup();
    if (session.Status().drained)
    {
        Require(session.Stop(), "idempotent stop failed");
        auto extra = session.Poll();
        Require(extra.outcome == PollOutcome::Done && extra.probes.empty() && extra.notices.empty(),
            "drained poll repeated data");
    }
    session.Close(); session.Close();
    Require(opened == closed, "session handle leak");
    // Decode all copied records only after the session has closed.
    std::cout << "ROUND\t" << round << '\n';
#ifdef PROCMON_TEST_NATIVE_DECODER
    if (decoder)
    {
        auto streamed = typed.size();
        auto final = decoder->Finish(session.Status(), interrupted != 0);
        Require(!final.issue || mode == "drop", "native decoder finalization failed");
        for (auto& event : final.events) typed.push_back(std::move(event));
        Require(decoder->Report().complete == (mode == "normal"), "false decoder completeness");
        RenderDecoder(batches, child.pid, typed, decoder->Report(), streamed);
    }
    else
#endif
        std::cout << Render(batches, child.pid, mode == "sigint" || mode == "sigterm");
    const auto& state = session.Status();
    auto elapsed = cancelStart == Clock::time_point{} ? 0 :
        std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - cancelStart).count();
    std::cout << "SESSION_STATUS\tround=" << round << "\tpid=" << child.pid << "\tmode=" << mode
              << "\topened=" << state.opened << "\tstarted=" << state.started << "\tstopped=" << state.stopped
              << "\tdrained=" << state.drained << "\tclosed=" << state.closed << "\tfailed=" << state.failed
              << "\tdiscarded=" << state.discarded << "\tprobes=" << state.probes
              << "\trecords=" << state.dataRecords << "\tzero=" << state.zeroRecords
              << "\terrors=" << state.runtimeErrors << "\tdrops=" << state.drops
              << "\treaped=" << child.reaped << "\tchild=" << child.status << "\tblocked=" << blocked
              << "\tsignal=" << interrupted << "\tcancel_ns=" << elapsed
              << "\topens=" << opened << "\tcloses=" << closed << '\n';
    if (state.failed) std::cerr << "SESSION_FAILURE\t" << state.diagnostic << '\n';
    Require(mode == "startup" ? state.failed && !state.started && state.closed :
        mode == "limit" ? state.failed && state.discarded : mode == "abandon" ? state.discarded && !state.drained :
        state.started && state.stopped && state.drained && state.closed && !state.failed && !state.discarded,
        "unexpected lifecycle outcome");
    Require(mode != "fault" || state.runtimeErrors > 0, "missing real fault callback");
    Require(mode != "drop" || state.drops > 0, "drop case unverified: no real drop");
    Require((mode != "sigint" && mode != "sigterm") ||
        (blocked && interrupted == (mode == "sigint" ? SIGINT : SIGTERM) && elapsed < 2000000000),
        "signal cleanup failed");
}

int main(int argc, char** argv)
{
    try
    {
#ifdef PROCMON_TEST_NATIVE_DECODER
        Require(argc == 7 || (argc == 8 && std::string(argv[7]) == "--decode"), "invalid decoder harness arguments");
        decodeEvents = argc == 8;
#else
        Require(argc == 7, "usage: test_dtrace_session script fixture directory uid gid mode");
#endif
        std::string mode = argv[6], uid = argv[4], gid = argv[5];
        Require(mode == "normal" || mode == "fault" || mode == "drop" || mode == "startup" ||
            mode == "sigint" || mode == "sigterm" || mode == "limit" || mode == "abandon" || mode == "denied",
            "unknown mode");
#ifdef PROCMON_TEST_NATIVE_DECODER
        Require(!decodeEvents || mode == "normal" || mode == "sigint" || mode == "sigterm" || mode == "drop",
            "unsupported decoder harness mode");
#endif
        Require(std::stoul(uid) > 0 && std::stoul(uid) <= std::numeric_limits<uid_t>::max() &&
            std::stoul(gid) <= std::numeric_limits<gid_t>::max(), "invalid fixture identity");
        std::ifstream input(argv[1]);
        Require(input.good(), "cannot open D source");
        std::string program((std::istreambuf_iterator<char>(input)), {});
        if (mode == "denied")
        {
            DTraceSession session;
            Require(!session.Start(program, {"1", "0"}) && session.Status().closed &&
                session.Status().failed && !session.Status().opened && opened == closed,
                "ordinary-user denial unverified");
            std::cout << "DENIED\t" << session.Status().diagnostic << '\n';
            return 0;
        }
        struct sigaction action{};
        action.sa_handler = Signal;
        sigemptyset(&action.sa_mask);
        Require(sigaction(SIGINT, &action, nullptr) == 0 && sigaction(SIGTERM, &action, nullptr) == 0,
            "signal handler setup failed");
        signal(SIGPIPE, SIG_IGN);
        for (int round = 1; round <= (mode == "normal" ? 2 : 1); ++round)
        {
            std::string directory = std::string(argv[3]) + "/run" + std::to_string(round);
            Require(mkdir(directory.c_str(), 0700) == 0 &&
                chown(directory.c_str(), static_cast<uid_t>(std::stoul(uid)), static_cast<gid_t>(std::stoul(gid))) == 0,
                "private round directory failed");
            Run(program, argv[2], directory, uid, gid, mode, round);
        }
        if (mode == "normal")
        {
            unsigned int beforeOpen = opened, beforeClose = closed, beforeStop = stopped;
            { DTraceSession session; Require(session.Start("BEGIN { trace((uint64_t)1); }", {}), "destructor test startup"); }
            Require(opened == beforeOpen + 1 && closed == beforeClose + 1 && stopped == beforeStop + 1,
                "active destructor cleanup failed");
            std::cout << "DESTRUCTOR_TEST\topens=1\tcloses=1\tstops=1\tpassed=1\n";
        }
        return std::cout.good() ? 0 : 1;
    }
    catch (const std::exception& error)
    {
        std::cerr << "SESSION_TEST_FAILURE\t" << error.what() << '\n';
        return 1;
    }
}
