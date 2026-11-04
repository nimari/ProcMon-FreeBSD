// SPDX-License-Identifier: MIT
// Bind real probes to an inspected child, then prove altered identities exclude it.
#include "../../src/tracer/freebsd/diagnostic/target_watch.h"
#include "../../src/tracer/freebsd/diagnostic/support.h"
#include <sys/wait.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <chrono>
#include <fstream>
#include <iostream>
#include <thread>
using namespace procmon::freebsd;
namespace d = procmon::freebsd::diagnostic;
static void Check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
int main(int argc, char** argv)
{
    pid_t child = -1;
    try
    {
        Check(argc == 6 && getuid() == 0, "usage: fixture dir uid gid profile (root)");
        const std::string profile = argv[5], output = std::string(argv[2]) + "/guard-" + profile + ".fixture";
        int gate[2], control[2]; Check(pipe(gate) == 0 && pipe(control) == 0, "pipes");
        child = fork(); Check(child >= 0, "fork");
        if (!child)
        {
            close(gate[1]); close(control[1]);
            int fd = open(output.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd < 0 || dup2(fd, STDOUT_FILENO) < 0) _exit(120);
            close(fd);
            if (setgroups(0, nullptr) || setgid(static_cast<gid_t>(std::stoul(argv[4]))) || setuid(static_cast<uid_t>(std::stoul(argv[3])))) _exit(121);
            const auto gateFd = std::to_string(gate[0]), controlFd = std::to_string(control[0]);
            execl(argv[1], argv[1], argv[2], argv[3], argv[4], gateFd.c_str(), controlFd.c_str(), "oracle", argv[1], static_cast<char*>(nullptr));
            _exit(122);
        }
        close(gate[0]); close(control[0]);
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);
        for (;;)
        {
            std::ifstream in(output); const std::string text{std::istreambuf_iterator<char>(in), {}};
            if (text.find("TARGET_READY") != text.npos) break;
            Check(std::chrono::steady_clock::now() < deadline, "fixture readiness");
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        d::TargetWatch watch; watch.Arm(child);
        CaptureConfiguration configuration;
        configuration.targetPid = child;
        configuration.operations = {NativeOperation::OpenAt, NativeOperation::Read, NativeOperation::Write};
        configuration.identity = watch.identity;
        if (profile == "address") ++configuration.identity->processAddress;
        else if (profile == "seconds") ++configuration.identity->startSeconds;
        else if (profile == "microseconds") configuration.identity->startMicroseconds = (configuration.identity->startMicroseconds + 1) % 1000000;
        else Check(profile == "matching", "profile");
        NativeCapture capture; Check(capture.Start(configuration), "capture start");
        Check(write(gate[1], "g", 1) == 1, "release"); close(gate[1]); close(control[1]);
        bool stopping = false;
        std::size_t events = 0;
        for (;;)
        {
            Check(std::chrono::steady_clock::now() < deadline, "capture timeout");
            if (!stopping && watch.Poll() == d::TargetChange::Exit)
            { capture.RequestStop(CaptureEndReason::Completed); stopping = true; }
            const auto update = capture.Poll();
            for (const auto& event : update.events) { d::Event(std::cout, event); ++events; }
            if (update.finished) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        const auto report = capture.Report(); d::Summary(std::cout, report, 0);
        Check(report.complete && (profile == "matching" ? events >= 6 : events == 0), "guard event selection");
        int status; Check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "fixture status");
        child = -1;
    }
    catch (const std::exception& error)
    { if (child > 0) { kill(child, SIGKILL); waitpid(child, nullptr, 0); } std::cerr << error.what() << '\n'; return 1; }
}
