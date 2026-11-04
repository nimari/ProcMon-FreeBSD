// SPDX-License-Identifier: MIT
// Bounded, isolated PID/filter validation. Process policy is test-only.
#include "../../src/tracer/freebsd/native_program.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dtrace.h>
#include <fcntl.h>
#include <grp.h>
#include <unistd.h>
#include <signal.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <thread>
#include <utility>

using namespace procmon::freebsd;
static void Check(bool value, const char* message)
{ if (!value) throw std::runtime_error(message); }
static std::int64_t Signed(std::uint64_t bits)
{ std::int64_t value; std::memcpy(&value, &bits, 8); return value; }

struct Child
{
    pid_t pid = -1;
    int gate = -1, status = -1;
    bool reaped = false;
    Child(const std::string& fixture, const std::string& directory, const std::string& uid, const std::string& gid)
    {
        const std::string output = directory + "/fixture.tsv";
        int token[2], ready[2];
        Check(pipe2(token, O_CLOEXEC) == 0, "gate pipe failed");
        if (pipe2(ready, O_CLOEXEC) != 0)
        { close(token[0]); close(token[1]); throw std::runtime_error("ready pipe failed"); }
        pid = fork();
        if (pid < 0)
        { for (int fd : {token[0], token[1], ready[0], ready[1]}) close(fd); throw std::runtime_error("fork failed"); }
        if (pid == 0)
        {
            alarm(12);
            close(token[1]); close(ready[0]);
            char byte;
            if (setgroups(0, nullptr) || setgid(static_cast<gid_t>(std::stoul(gid))) ||
                setuid(static_cast<uid_t>(std::stoul(uid))) || write(ready[1], "r", 1) != 1)
                _exit(125);
            close(ready[1]);
            if (read(token[0], &byte, 1) != 1) _exit(125);
            close(token[0]);
            int fd = open(output.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
            if (fd < 0 || dup2(fd, STDOUT_FILENO) < 0) _exit(125);
            close(fd);
            execl(fixture.c_str(), fixture.c_str(), directory.c_str(), uid.c_str(), gid.c_str(), static_cast<char*>(nullptr));
            _exit(126);
        }
        close(token[0]); close(ready[1]);
        char byte;
        ssize_t count;
        do { count = read(ready[0], &byte, 1); } while (count < 0 && errno == EINTR);
        close(ready[0]); gate = token[1];
        if (count != 1 || byte != 'r')
        { Cleanup(); throw std::runtime_error("fixture ready handshake failed"); }
    }
    void Release()
    { Check(write(gate, "x", 1) == 1, "release failed"); close(gate); gate = -1; }
    void Reap(bool wait = false)
    {
        if (reaped) return;
        int value; pid_t result;
        do { result = waitpid(pid, &value, wait ? 0 : WNOHANG); } while (result < 0 && errno == EINTR);
        Check(result >= 0, "reap failed");
        if (result == pid)
        { reaped = true; status = WIFEXITED(value) ? WEXITSTATUS(value) : 128 + WTERMSIG(value); }
    }
    void Cleanup()
    {
        if (gate >= 0) { close(gate); gate = -1; }
        if (!reaped) { kill(pid, SIGKILL); Reap(true); }
    }
    ~Child() { try { Cleanup(); } catch (...) {} }
};

static void Evidence(const std::string& path, const std::string& source, uid_t uid, gid_t gid)
{
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    Check(fd >= 0, "evidence file failed");
    bool okay = fchown(fd, uid, gid) == 0;
    std::size_t offset = 0;
    while (okay && offset < source.size())
    {
        ssize_t count = write(fd, source.data() + offset, source.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) okay = false;
        else offset += static_cast<std::size_t>(count);
    }
    okay = close(fd) == 0 && okay;
    Check(okay, "evidence write failed");
}

static void MonitorWorkload(const std::string& directory)
{
    std::string path = directory + "/monitor-file", missing = path + "-missing";
    char buffer[8]; const char data[] = "monitor!";
    int fd = openat(AT_FDCWD, path.c_str(), O_CREAT | O_EXCL | O_RDWR, 0600);
    Check(fd >= 0, "monitor open failed");
    bool okay = write(fd, data, 8) == 8 && lseek(fd, 0, SEEK_SET) == 0 && read(fd, buffer, 8) == 8;
    okay = okay && std::memcmp(buffer, data, 8) == 0;
    errno = 0; okay = (read(-1, buffer, 1) == -1 && errno == EBADF) && okay;
    errno = 0; okay = (write(-1, data, 1) == -1 && errno == EBADF) && okay;
    errno = 0; okay = (openat(AT_FDCWD, missing.c_str(), O_RDONLY) == -1 && errno == ENOENT) && okay;
    okay = close(fd) == 0 && okay; okay = unlink(path.c_str()) == 0 && okay;
    Check(okay, "monitor workload failed");
}

static const char* Name(NativeOperation operation)
{ return operation == NativeOperation::OpenAt ? "openat" : operation == NativeOperation::Read ? "read" : "write"; }

static void Raw(const std::vector<SessionBatch>& batches)
{
    for (const auto& batch : batches)
        for (const auto& probe : batch.probes)
        {
            std::vector<std::uint64_t> values;
            std::string path;
            for (const auto& record : probe.records)
            {
                Check(record.action == DTRACEACT_DIFEXPR, "unexpected raw action");
                if (record.bytes.empty()) continue;
                if (record.bytes.size() == 8)
                { std::uint64_t value; std::memcpy(&value, record.bytes.data(), 8); values.push_back(value); }
                else
                {
                    Check(record.bytes.size() == 65 && std::memchr(record.bytes.data(), 0, 65), "raw path bounds");
                    path = reinterpret_cast<const char*>(record.bytes.data());
                }
            }
            if (probe.provider == "dtrace")
            {
                Check(values.size() == 2 && (probe.name == "BEGIN" || probe.name == "END"), "raw boundary");
                std::cout << "BOUNDARY\t" << probe.name << '\t' << values[0] << '\t' << values[1] << '\n';
                continue;
            }
            bool entry = probe.name == "entry";
            Check(probe.provider == "syscall" && probe.module == "freebsd" &&
                (entry || probe.name == "return") && values.size() == (entry ? 5U : 8U), "raw ABI/width");
            std::cout << (entry ? "RAW_ENTRY" : "RAW_RETURN") << '\t' << values[0] << '\t' << values[1]
                      << '\t' << probe.function << '\t' << values[2] << '\t';
            if (entry) std::cout << Signed(values[3]) << '\t' << values[4];
            else std::cout << values[3] << '\t' << Signed(values[4]) << '\t' << values[5]
                           << '\t' << Signed(values[6]) << '\t' << values[7];
            std::cout << '\t' << path << '\n';
        }
}

int main(int argc, char** argv)
{
    try
    {
        Check(argc == 6, "usage: test_native_program_capture fixture directory uid gid profile");
        std::string profile = argv[5], directory = argv[2], uidText = argv[3], gidText = argv[4];
        unsigned long uidValue = std::stoul(uidText), gidValue = std::stoul(gidText);
        Check(uidValue > 0 && uidValue <= std::numeric_limits<uid_t>::max() &&
            gidValue <= std::numeric_limits<gid_t>::max(), "invalid identity");
        uid_t uid = static_cast<uid_t>(uidValue); gid_t gid = static_cast<gid_t>(gidValue);
        unsigned int mask = profile == "openat" ? 1 : profile == "read" ? 2 : profile == "write" ? 4 :
            profile == "openat-read" ? 3 : profile == "openat-write" ? 5 : profile == "read-write" ? 6 :
            (profile == "all" || profile == "unmarked" || profile == "self") ? 7 : 0;
        Check(mask != 0, "unknown profile");
        signal(SIGPIPE, SIG_IGN);
        for (const char* role : {"target", "noise"})
        {
            auto path = directory + "/" + role;
            Check(mkdir(path.c_str(), 0700) == 0 && chown(path.c_str(), uid, gid) == 0, "private child directory failed");
        }
        Child target(argv[1], directory + "/target", uidText, gidText);
        Child noise(argv[1], directory + "/noise", uidText, gidText);
        auto monitor = static_cast<std::uint64_t>(getpid());
        NativeProgramRequest request{profile == "self" ? monitor : static_cast<std::uint64_t>(target.pid), monitor, {}};
        for (unsigned int bit = 0; bit < 3; ++bit)
            if (mask & (1U << bit)) request.operations.push_back(static_cast<NativeOperation>(bit));
        auto program = BuildNativeProgram(request);
        Evidence(directory + "/generated-source.txt", program.source, uid, gid);
        NativeEventDecoder decoder(request.targetPid);
        std::vector<NativeEvent> events;
        std::vector<SessionBatch> batches;
        DTraceSession session;
        Check(session.Start(program.source, {}), session.Status().diagnostic.c_str());
        MonitorWorkload(directory);
        target.Release(); noise.Release();
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        for (;;)
        {
            Check(std::chrono::steady_clock::now() < deadline, "capture watchdog expired");
            target.Reap(); noise.Reap();
            if (target.reaped && noise.reaped) Check(session.Stop(), "stop failed");
            auto batch = session.Poll();
            auto decoded = decoder.Consume(batch);
            Check(!decoded.issue, "generated program decoder rejected a record");
            for (auto& event : decoded.events) events.push_back(std::move(event));
            auto outcome = batch.outcome;
            batches.push_back(std::move(batch));
            Check(session.Status().runtimeErrors == 0 && session.Status().drops == 0, "generated capture error/loss");
            if (outcome == PollOutcome::Done) break;
            Check(outcome != PollOutcome::Error, "poll failed");
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        session.Close();
        auto final = decoder.Finish(session.Status(), false);
        for (auto& event : final.events) events.push_back(std::move(event));
        const auto& report = decoder.Report();
        Check(report.complete && !final.issue && target.reaped && noise.reaped &&
            target.status == 0 && noise.status == 0, "incomplete generated capture/fixture");
        Check((profile == "self") == events.empty(), "self-exclusion or positive capture failed");
        Raw(batches);
        for (const auto& event : events)
        {
            Check(event.state == NativeEventState::Completed && event.pid == request.targetPid &&
                event.timestampNs && event.durationNs && event.result && event.error, "typed event validity");
            std::cout << "EVENT\t" << event.pid << '\t' << event.tid << '\t' << Name(event.operation)
                      << '\t' << event.correlationStartNs << '\t' << *event.timestampNs << '\t' << *event.durationNs
                      << '\t' << *event.result << '\t' << *event.error << '\t' << event.arguments.descriptor
                      << '\t' << event.arguments.third << '\t' << event.arguments.path.has_value()
                      << '\t' << (event.arguments.path && event.arguments.path->atCaptureLimit)
                      << '\t' << (event.arguments.path ? event.arguments.path->text : "-") << '\n';
        }
        const auto& state = session.Status();
        std::cout << "PROGRAM_REPORT\tprofile=" << profile << "\tmask=" << mask << "\ttarget=" << request.targetPid
                  << "\tmonitor=" << monitor << "\tfixture=" << target.pid << "\tnoise=" << noise.pid
                  << "\tchild_a=" << target.status << "\tchild_b=" << noise.status << "\tmonitor_calls=6"
                  << "\tcomplete=" << report.complete << "\tevents=" << events.size() << "\tstarted=" << state.started
                  << "\tstopped=" << state.stopped << "\tdrained=" << state.drained << "\tclosed=" << state.closed
                  << "\tfailed=" << state.failed << "\tdiscarded=" << state.discarded
                  << "\tprobes=" << state.probes << "\trecords=" << state.dataRecords << "\tzero=" << state.zeroRecords
                  << "\terrors=" << state.runtimeErrors << "\tdrops=" << state.drops << '\n';
        return std::cout.good() ? 0 : 1;
    }
    catch (const std::exception& error) { std::cerr << "PROGRAM_TEST_FAILURE\t" << error.what() << '\n'; return 1; }
}
