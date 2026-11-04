// SPDX-License-Identifier: MIT
// Controller tests only: child ownership and native API fault injection live here.
#include "../../src/tracer/freebsd/native_capture.h"
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
#include <iostream>
#include <limits>
#include <stdexcept>
#include <thread>
#include <utility>

using namespace procmon::freebsd;
using Clock = std::chrono::steady_clock;
static std::string profile;
static unsigned int opens, closes, stops, realStops, injected;
static pid_t expectedPid;
static int expectedFd;
static bool blocked, callbackFailed;
static volatile sig_atomic_t signalSeen;
static dtrace_consume_probe_f* forwardProbe;
static std::vector<CapturedProbe> raw;
static void Check(bool value, const char* message)
{ if (!value) throw std::runtime_error(message); }
static void Signal(int value) { signalSeen = value; }
static std::int64_t Signed(std::uint64_t value)
{ std::int64_t result; std::memcpy(&result, &value, 8); return result; }
static std::vector<std::uint64_t> Values(const CapturedProbe& probe, std::string& path)
{
    std::vector<std::uint64_t> values;
    for (const auto& record : probe.records)
    {
        Check(record.action == DTRACEACT_DIFEXPR, "raw action");
        if (record.bytes.empty()) continue;
        if (record.bytes.size() == 8)
        { std::uint64_t value; std::memcpy(&value, record.bytes.data(), 8); values.push_back(value); }
        else
        { Check(record.bytes.size() == 65 && std::memchr(record.bytes.data(), 0, 65), "raw path"); path = reinterpret_cast<const char*>(record.bytes.data()); }
    }
    return values;
}
static int Observe(const dtrace_probedata_t* data, void* argument) noexcept
{
    try
    {
        Check(raw.size() < 4096 && data->dtpda_edesc->dtepd_nrecs >= 0, "test observation bound");
        const auto& p = *data->dtpda_pdesc;
        CapturedProbe copy{p.dtpd_provider, p.dtpd_mod, p.dtpd_func, p.dtpd_name, data->dtpda_cpu, {}};
        for (int index = 0; index < data->dtpda_edesc->dtepd_nrecs; ++index)
        {
            const auto& record = data->dtpda_edesc->dtepd_rec[index];
            Check(record.dtrd_offset <= data->dtpda_edesc->dtepd_size &&
                record.dtrd_size <= data->dtpda_edesc->dtepd_size - record.dtrd_offset, "test payload bounds");
            CapturedRecord field{record.dtrd_action, record.dtrd_arg, record.dtrd_alignment, {}};
            if (record.dtrd_size)
            {
                const auto* start = reinterpret_cast<const std::uint8_t*>(data->dtpda_data) + record.dtrd_offset;
                field.bytes.assign(start, start + record.dtrd_size);
            }
            copy.records.push_back(std::move(field));
        }
        if (copy.provider == "syscall" && copy.function == "read" && copy.name == "entry")
        {
            std::string path; auto values = Values(copy, path);
            if (values.size() == 5 && values[0] == static_cast<std::uint64_t>(expectedPid) &&
                values[3] == static_cast<std::uint64_t>(expectedFd) && values[4] == 1) blocked = true;
        }
        raw.push_back(std::move(copy));
    }
    catch (...) { callbackFailed = true; return DTRACE_CONSUME_ABORT; }
    return forwardProbe(data, argument);
}
extern "C"
{
dtrace_hdl_t* __real_dtrace_open(int, int, int*);
void __real_dtrace_close(dtrace_hdl_t*);
int __real_dtrace_stop(dtrace_hdl_t*);
int __real_dtrace_go(dtrace_hdl_t*);
int __real_dtrace_program_exec(dtrace_hdl_t*, dtrace_prog_t*, dtrace_proginfo_t*);
dtrace_prog_t* __real_dtrace_program_strcompile(dtrace_hdl_t*, const char*, dtrace_probespec_t, uint_t, int, char* const[]);
dtrace_workstatus_t __real_dtrace_work(dtrace_hdl_t*, FILE*, dtrace_consume_probe_f*, dtrace_consume_rec_f*, void*);
dtrace_hdl_t* __wrap_dtrace_open(int version, int flags, int* error)
{ auto* handle = __real_dtrace_open(version, flags, error); opens += handle != nullptr; return handle; }
void __wrap_dtrace_close(dtrace_hdl_t* handle) { ++closes; __real_dtrace_close(handle); }
int __wrap_dtrace_stop(dtrace_hdl_t* handle)
{
    ++stops;
    if (profile == "stop" && !injected) { ++injected; return -1; }
    ++realStops; return __real_dtrace_stop(handle);
}
int __wrap_dtrace_go(dtrace_hdl_t* handle)
{ if (profile == "go") { ++injected; return -1; } return __real_dtrace_go(handle); }
int __wrap_dtrace_program_exec(dtrace_hdl_t* handle, dtrace_prog_t* program, dtrace_proginfo_t* info)
{ if (profile == "enable") { ++injected; return -1; } return __real_dtrace_program_exec(handle, program, info); }
dtrace_prog_t* __wrap_dtrace_program_strcompile(dtrace_hdl_t* handle, const char* source,
    dtrace_probespec_t spec, uint_t flags, int argc, char* const argv[])
{
    if (profile == "compile") { ++injected; source = "this is not valid D;"; }
    return __real_dtrace_program_strcompile(handle, source, spec, flags, argc, argv);
}
dtrace_workstatus_t __wrap_dtrace_work(dtrace_hdl_t* handle, FILE* output,
    dtrace_consume_probe_f* probe, dtrace_consume_rec_f* record, void* argument)
{
    if (profile == "work") { ++injected; return DTRACE_WORKSTATUS_ERROR; }
    forwardProbe = probe;
    return __real_dtrace_work(handle, output, Observe, record, argument);
}
}

struct Child
{
    pid_t pid = -1;
    int gate = -1, control = -1, blockedFd = -1, status = -1;
    bool reaped = false;
    Child(const std::string& fixture, const std::string& directory, const std::string& uid,
        const std::string& gid, bool controlled, bool fault)
    {
        std::string output = directory + "/fixture.tsv";
        int token[2] = {-1, -1}, ready[2] = {-1, -1}, channel[2] = {-1, -1};
        if (pipe2(token, O_CLOEXEC) || pipe2(ready, O_CLOEXEC) || pipe2(channel, O_CLOEXEC))
        {
            for (int fd : {token[0], token[1], ready[0], ready[1], channel[0], channel[1]}) if (fd >= 0) close(fd);
            throw std::runtime_error("pipe setup");
        }
        blockedFd = channel[0]; std::string fdText = std::to_string(blockedFd);
        pid = fork();
        if (pid < 0)
        {
            for (int fd : {token[0], token[1], ready[0], ready[1], channel[0], channel[1]}) close(fd);
            throw std::runtime_error("fork");
        }
        if (!pid)
        {
            alarm(12); close(token[1]); close(ready[0]); close(channel[1]);
            char byte;
            if (setgroups(0, nullptr) || setgid(static_cast<gid_t>(std::stoul(gid))) ||
                setuid(static_cast<uid_t>(std::stoul(uid))) || write(ready[1], "r", 1) != 1) _exit(125);
            close(ready[1]);
            if (read(token[0], &byte, 1) != 1) _exit(125);
            close(token[0]);
            int fd = open(output.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
            if (fd < 0 || dup2(fd, STDOUT_FILENO) < 0) _exit(125);
            close(fd);
            if (controlled)
            {
                if (fcntl(channel[0], F_SETFD, 0)) _exit(125);
                execl(fixture.c_str(), fixture.c_str(), directory.c_str(), uid.c_str(), gid.c_str(),
                    fdText.c_str(), fault ? "fault" : "blocked", static_cast<char*>(nullptr));
            }
            else
                execl(fixture.c_str(), fixture.c_str(), directory.c_str(), uid.c_str(), gid.c_str(), static_cast<char*>(nullptr));
            _exit(126);
        }
        close(token[0]); close(ready[1]); close(channel[0]);
        gate = token[1]; control = channel[1];
        char byte; ssize_t count;
        do { count = read(ready[0], &byte, 1); } while (count < 0 && errno == EINTR);
        close(ready[0]);
        if (count != 1 || byte != 'r') { Cleanup(); throw std::runtime_error("ready handshake"); }
    }
    void Release() { Check(write(gate, "x", 1) == 1, "gate release"); close(gate); gate = -1; }
    void Unblock() { Check(write(control, "x", 1) == 1, "blocked target release"); close(control); control = -1; }
    void Reap(bool wait = false)
    {
        if (reaped) return;
        int value; pid_t result;
        do { result = waitpid(pid, &value, wait ? 0 : WNOHANG); } while (result < 0 && errno == EINTR);
        Check(result >= 0, "waitpid");
        if (result == pid) { reaped = true; status = WIFEXITED(value) ? WEXITSTATUS(value) : 128 + WTERMSIG(value); }
    }
    void Cleanup()
    {
        if (gate >= 0) { close(gate); gate = -1; }
        if (control >= 0) { close(control); control = -1; }
        if (pid > 0 && !reaped) { kill(pid, SIGKILL); Reap(true); }
    }
    ~Child() { try { Cleanup(); } catch (...) {} }
};

static void SelfWorkload(const std::string& directory)
{
    auto path = directory + "/self-file";
    int fd = openat(AT_FDCWD, path.c_str(), O_CREAT | O_EXCL | O_RDWR, 0600);
    Check(fd >= 0, "self workload open");
    char byte = 'x', result;
    bool okay = write(fd, &byte, 1) == 1 && lseek(fd, 0, SEEK_SET) == 0 && read(fd, &result, 1) == 1 && result == byte;
    okay = close(fd) == 0 && okay; okay = unlink(path.c_str()) == 0 && okay;
    Check(okay, "self workload I/O");
}

static const char* Name(NativeOperation op)
{ return op == NativeOperation::OpenAt ? "openat" : op == NativeOperation::Read ? "read" : "write"; }
static void Render(const CaptureReport& report, const std::vector<NativeEvent>& events,
    const std::vector<SessionNotice>& notices, int round, const Child& child, bool alive, std::int64_t cancelNs)
{
    std::cout << "ROUND\t" << round << '\n';
    for (const auto& probe : raw)
    {
        std::string path; auto v = Values(probe, path);
        if (probe.provider == "dtrace")
        { Check(v.size() == 2, "boundary schema"); std::cout << "BOUNDARY\t" << probe.name << '\t' << v[0] << '\t' << v[1] << '\n'; continue; }
        bool entry = probe.name == "entry";
        Check(v.size() == (entry ? 5U : 8U), "raw scalar schema");
        std::cout << (entry ? "RAW_ENTRY" : "RAW_RETURN") << '\t' << v[0] << '\t' << v[1] << '\t' << probe.function << '\t' << v[2] << '\t';
        if (entry) std::cout << Signed(v[3]) << '\t' << v[4];
        else std::cout << v[3] << '\t' << Signed(v[4]) << '\t' << v[5] << '\t' << Signed(v[6]) << '\t' << v[7];
        std::cout << '\t' << path << '\n';
    }
    for (const auto& event : events)
    {
        std::cout << "EVENT\t" << event.pid << '\t' << event.tid << '\t' << Name(event.operation) << '\t' << event.correlationStartNs
                  << '\t' << static_cast<int>(event.state) << '\t' << event.entryPresent << '\t' << event.returnPresent
                  << '\t' << event.timestampNs.has_value() << '\t' << event.timestampNs.value_or(0)
                  << '\t' << event.durationNs.has_value() << '\t' << event.durationNs.value_or(0)
                  << '\t' << event.result.has_value() << '\t' << event.result.value_or(0)
                  << '\t' << event.error.has_value() << '\t' << event.error.value_or(0)
                  << '\t' << (event.returned ? event.returned->result : 0) << '\t' << (event.returned ? event.returned->errnoBits : 0)
                  << '\t' << event.arguments.descriptor << '\t' << event.arguments.third
                  << '\t' << event.arguments.path.has_value() << '\t' << (event.arguments.path && event.arguments.path->atCaptureLimit)
                  << '\t' << (event.arguments.path ? event.arguments.path->text : "-") << '\n';
    }
    for (const auto& notice : notices)
        std::cout << "NOTICE\t" << static_cast<int>(notice.kind) << '\t' << notice.count << '\n';
    const auto& s = report.session;
    std::cout << "CONTROLLER_REPORT\tprofile=" << profile << "\tround=" << round << "\ttarget=" << report.targetPid
              << "\tmonitor=" << report.monitorPid << "\tactual_monitor=" << getpid() << "\tfixture=" << child.pid
              << "\tphase=" << static_cast<int>(report.phase) << "\treason=" << static_cast<int>(report.reason)
              << "\tcomplete=" << report.complete << "\trequested=" << report.stopRequested << "\tcancel=" << report.cancellationRequested
              << "\topened=" << s.opened << "\tstarted=" << s.started << "\tstopped=" << s.stopped << "\tdrained=" << s.drained
              << "\tclosed=" << s.closed << "\tfailed=" << s.failed << "\tdiscarded=" << s.discarded
              << "\tprobes=" << s.probes << "\trecords=" << s.dataRecords << "\tzero=" << s.zeroRecords
              << "\terrors=" << s.runtimeErrors << "\tdrops=" << s.drops << "\tevents=" << events.size()
              << "\talive=" << alive << "\tchild=" << child.status << "\tblocked=" << blocked
              << "\tsignal=" << signalSeen << "\tcancel_ns=" << cancelNs << "\topens=" << opens << "\tcloses=" << closes
              << "\tstops=" << stops << "\treal_stops=" << realStops << "\tinjected=" << injected
              << "\tself_calls=" << (profile == "self" ? 3 : 0) << '\n';
    std::cout << "DECODER_REPORT\tpresent=" << report.decoder.has_value();
    if (report.decoder)
    {
        const auto& d = *report.decoder;
        std::cout << "\tfinalized=" << d.finalized << "\tcomplete=" << d.complete << "\tcompleted=" << d.completed
                  << "\tcancelled=" << d.cancelled << "\tincomplete=" << d.incomplete << "\tissue="
                  << (d.issue ? static_cast<int>(d.issue->kind) : -1) << "\tstart=" << d.startNs.value_or(0)
                  << "\tend=" << d.endNs.value_or(0);
    }
    std::cout << '\n';
    if (!report.diagnostic.empty()) std::cout << "DIAGNOSTIC\t" << report.diagnostic << '\n';
}

static void Run(const std::string& fixture, const std::string& directory,
    const std::string& uid, const std::string& gid, int round)
{
    raw.clear(); blocked = callbackFailed = false; signalSeen = 0;
    bool controlled = profile == "cancel" || profile == "sigint" || profile == "sigterm" || profile == "incomplete" || profile == "fault";
    Child child(fixture, directory, uid, gid, controlled, profile == "fault");
    expectedPid = child.pid; expectedFd = child.blockedFd;
    CaptureConfiguration config;
    config.targetPid = profile == "self" ? static_cast<std::uint64_t>(getpid()) : static_cast<std::uint64_t>(child.pid);
    config.operations = {NativeOperation::OpenAt, NativeOperation::Read, NativeOperation::Write};
    if (profile == "drop") config.transport.bufferSize = "1k";
    if (profile == "limit") config.transport.maximumBatchBytes = 1;
    if (profile == "capacity") config.maximumPending = 1;
    if (profile == "option") config.transport.bufferSize = "invalid-size";
    auto capture = std::make_unique<NativeCapture>();
    bool started = capture->Start(config);
    if (started && profile == "self") SelfWorkload(directory);
    bool held = profile == "limit" || profile == "work" || profile == "stop" || profile == "abandon";
    if (started && !held) child.Release();
    if (started && profile == "stop") capture->RequestStop(CaptureEndReason::Completed);
    if (started && profile == "abandon") capture->Close();
    std::vector<NativeEvent> events;
    std::vector<SessionNotice> notices;
    bool finished = !started || profile == "abandon";
    auto deadline = Clock::now() + std::chrono::seconds(10);
    Clock::time_point cancelStart{};
    while (!finished)
    {
        Check(Clock::now() < deadline, "controller watchdog"); child.Reap();
        if (profile == "drop" && !child.reaped)
        { std::this_thread::sleep_for(std::chrono::milliseconds(5)); continue; }
        if (child.reaped) capture->RequestStop(CaptureEndReason::Completed);
        if (blocked && controlled && profile != "fault" && !capture->Report().stopRequested)
        {
            cancelStart = Clock::now();
            if (profile == "sigint" || profile == "sigterm")
                Check(kill(getpid(), profile == "sigint" ? SIGINT : SIGTERM) == 0, "self signal delivery");
            capture->RequestStop(profile == "incomplete" ? CaptureEndReason::Completed : CaptureEndReason::Cancelled);
        }
        auto update = capture->Poll();
        for (auto& event : update.events) events.push_back(std::move(event));
        for (auto& notice : update.notices) { Check(!notice.message.empty(), "lost notice message"); notices.push_back(std::move(notice)); }
        finished = update.finished;
        if (!finished) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    auto report = capture->Report();
    auto again = capture->Poll(); Check(again.finished && again.events.empty() && again.notices.empty(), "terminal delivery duplicated");
    capture->Close(); Check(capture->Report().reason == report.reason, "terminal close changed reason");
    capture.reset();
    auto cancelNs = cancelStart == Clock::time_point{} ? 0 :
        std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - cancelStart).count();
    child.Reap(); bool alive = !child.reaped;
    if (controlled || held || !started) Check(alive, "controller terminated its target");
    if (child.gate >= 0) child.Release();
    if (controlled) child.Unblock();
    child.Reap(true);
    Check(child.status == 0 && opens == closes && !callbackFailed, "target survival/handle/callback checks");
    Check(report.monitorPid == static_cast<std::uint64_t>(getpid()), "automatic monitor PID failed");
    if (profile == "normal" || profile == "self") Check(report.complete && report.reason == CaptureEndReason::Completed &&
        (profile != "self" || events.empty()), "normal capture/self exclusion failed");
    else if (profile == "cancel" || profile == "sigint" || profile == "sigterm")
        Check(!report.complete && report.reason == CaptureEndReason::Cancelled && report.decoder->cancelled == 1 && alive, "cancellation policy failed");
    else if (profile == "abandon") Check(report.reason == CaptureEndReason::Abandoned && report.phase == CapturePhase::Closed && report.session.discarded, "abandon policy failed");
    else Check(!report.complete && report.reason == CaptureEndReason::Failure, "failure reported as success");
    Render(report, events, notices, round, child, alive, cancelNs);
}

int main(int argc, char** argv)
{
    try
    {
        Check(argc == 6, "usage: test_native_capture_runtime fixture directory uid gid profile");
        profile = argv[5];
        Check(profile == "normal" || profile == "self" || profile == "cancel" || profile == "sigint" || profile == "sigterm" ||
            profile == "incomplete" || profile == "fault" || profile == "drop" || profile == "limit" || profile == "capacity" ||
            profile == "abandon" || profile == "option" || profile == "compile" || profile == "enable" || profile == "go" ||
            profile == "work" || profile == "stop" || profile == "denied", "unknown profile");
        Check(std::stoul(argv[3]) > 0 && std::stoul(argv[3]) <= std::numeric_limits<uid_t>::max() &&
            std::stoul(argv[4]) <= std::numeric_limits<gid_t>::max(), "invalid identity");
        struct sigaction action{}; action.sa_handler = Signal; sigemptyset(&action.sa_mask);
        Check(sigaction(SIGINT, &action, nullptr) == 0 && sigaction(SIGTERM, &action, nullptr) == 0, "signal setup");
        signal(SIGPIPE, SIG_IGN);
        if (profile == "denied")
        {
            NativeCapture capture; CaptureConfiguration config;
            config.targetPid = getpid(); config.operations = {NativeOperation::Read};
            Check(!capture.Start(config), "denied case unexpectedly granted");
            auto report = capture.Report();
            Check(report.reason == CaptureEndReason::Failure && !report.session.opened && report.session.closed && opens == closes,
                "denied cleanup");
            std::cout << "DENIED\t" << report.diagnostic << '\n'; return 0;
        }
        for (int round = 1; round <= (profile == "normal" ? 2 : 1); ++round)
        {
            std::string directory = std::string(argv[2]) + "/run" + std::to_string(round);
            Check(mkdir(directory.c_str(), 0700) == 0 && chown(directory.c_str(), std::stoul(argv[3]), std::stoul(argv[4])) == 0, "private round directory");
            Run(argv[1], directory, argv[3], argv[4], round);
        }
        if (profile == "normal")
        {
            unsigned int openedBefore = opens, closedBefore = closes, stoppedBefore = stops;
            { NativeCapture capture; CaptureConfiguration config; config.targetPid = getpid(); config.operations = {NativeOperation::Read};
              Check(capture.Start(config), "destructor startup"); }
            Check(opens == openedBefore + 1 && closes == closedBefore + 1 && stops == stoppedBefore + 1, "active destructor cleanup");
            std::cout << "DESTRUCTOR_TEST\topens=1\tcloses=1\tstops=1\tpassed=1\n";
        }
        return std::cout.good() ? 0 : 1;
    }
    catch (const std::exception& error) { std::cerr << "CAPTURE_TEST_FAILURE\t" << error.what() << '\n'; return 1; }
}
