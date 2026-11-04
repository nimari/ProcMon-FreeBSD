// SPDX-License-Identifier: MIT
// Test-only process supervisor. The diagnostic driver never owns/signals targets.
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <unistd.h>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

using Clock = std::chrono::steady_clock;
static pid_t target = -1, monitor = -1;
static void Check(bool value, const char* message)
{ if (!value) throw std::runtime_error(message); }
static std::string Read(const std::string& path)
{ std::ifstream in(path); return {std::istreambuf_iterator<char>(in), {}}; }
static void Await(const std::string& path, const char* text)
{
    auto deadline = Clock::now() + std::chrono::seconds(8);
    while (Read(path).find(text) == std::string::npos)
    {
        Check(Clock::now() < deadline, "output wait timeout");
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}
static int Wait(pid_t& child)
{
    int status = 0;
    auto deadline = Clock::now() + std::chrono::seconds(8);
    for (;;)
    {
        auto result = waitpid(child, &status, WNOHANG);
        if (result == child) { child = -1; break; }
        Check(result == 0 || (result == -1 && errno == EINTR), "waitpid");
        Check(Clock::now() < deadline, "child wait timeout");
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    Check(WIFEXITED(status), "child terminated by signal");
    return WEXITSTATUS(status);
}
static void Redirect(const std::string& path, int descriptor)
{
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || dup2(fd, descriptor) < 0) _exit(120);
    close(fd);
}
static void Cleanup() noexcept
{
    // Only children created by this test, and only on test failure.
    for (auto child : {target, monitor}) if (child > 0) { kill(child, SIGKILL); waitpid(child, nullptr, 0); }
}
int main(int argc, char** argv)
{
    try
    {
        Check(argc == 8 && getuid() == 0, "usage: pilot fixture controlled dir uid gid profile (as root)");
        const std::string pilot = argv[1], fixture = argv[2], controlled = argv[3], directory = argv[4], profile = argv[7];
        const auto uid = static_cast<uid_t>(std::stoul(argv[5]));
        const auto gid = static_cast<gid_t>(std::stoul(argv[6]));
        const bool self = profile == "self", broken = profile == "broken";
        const bool blocking = profile == "cancel" || profile == "term" || profile == "fault" || broken;
        Check(self || blocking || profile == "all" || profile == "read" || profile == "write" || profile == "openat", "profile");
        int gate[2], control[2];
        Check(pipe(gate) == 0 && pipe(control) == 0, "pipes");
        const auto prefix = directory + "/" + profile;
        const auto fixtureDirectory = prefix + "-files";
        Check(mkdir(fixtureDirectory.c_str(), 0700) == 0 && chown(fixtureDirectory.c_str(), uid, gid) == 0, "fixture directory");
        if (!self)
        {
            target = fork(); Check(target >= 0, "target fork");
            if (target == 0)
            {
                close(gate[1]); close(control[1]);
                Redirect(prefix + ".fixture", STDOUT_FILENO); Redirect(prefix + ".fixture-error", STDERR_FILENO);
                if (setgroups(0, nullptr) || setgid(gid) || setuid(uid)) _exit(121);
                char byte;
                if (read(gate[0], &byte, 1) != 1) _exit(122);
                close(gate[0]);
                const auto fd = std::to_string(control[0]);
                if (blocking) execl(controlled.c_str(), controlled.c_str(), fixtureDirectory.c_str(), argv[5], argv[6],
                    fd.c_str(), profile == "fault" ? "fault" : "blocked", static_cast<char*>(nullptr));
                else { close(control[0]); execl(fixture.c_str(), fixture.c_str(), fixtureDirectory.c_str(), argv[5], argv[6], static_cast<char*>(nullptr)); }
                _exit(123);
            }
        }
        close(gate[0]); close(control[0]);
        int outputPipe[2] = {-1, -1};
        if (broken) Check(pipe(outputPipe) == 0, "broken output pipe");
        monitor = fork(); Check(monitor >= 0, "monitor fork");
        if (monitor == 0)
        {
            close(gate[1]); close(control[1]);
            Redirect(prefix + ".stderr", STDERR_FILENO);
            if (broken)
            { close(outputPipe[0]); if (dup2(outputPipe[1], STDOUT_FILENO) < 0) _exit(124); close(outputPipe[1]); }
            else Redirect(prefix + ".jsonl", STDOUT_FILENO);
            const auto pid = std::to_string(self ? getpid() : target);
            const char* events = profile == "read" || profile == "write" || profile == "openat" ? profile.c_str() : "openat,read,write";
            execl(pilot.c_str(), pilot.c_str(), "--pid", pid.c_str(), "--events", events,
                "--duration-ms", blocking ? "5000" : "600", static_cast<char*>(nullptr));
            _exit(125);
        }
        const auto actualMonitor = monitor, actualTarget = self ? monitor : target;
        if (broken) { close(outputPipe[0]); close(outputPipe[1]); }
        else Await(prefix + ".jsonl", "\"type\":\"ready\"");
        if (!self && !broken) Check(write(gate[1], "g", 1) == 1, "release target");
        if (blocking && !broken)
        {
            Await(prefix + ".fixture", "BLOCK_EXPECT");
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
            if (profile != "fault") Check(kill(monitor, profile == "term" ? SIGTERM : SIGINT) == 0, "signal driver");
        }
        int monitorExit = Wait(monitor);
        int expected = profile == "cancel" ? 130 : profile == "term" ? 143 : profile == "fault" || broken ? 1 : 0;
        Check(monitorExit == expected, "driver exit status");
        bool alive = false;
        if (blocking)
        {
            alive = kill(target, 0) == 0; Check(alive, "target survived capture closure");
            if (broken) Check(write(gate[1], "g", 1) == 1, "release after output failure");
            Check(write(control[1], "c", 1) == 1, "release blocked read");
        }
        close(gate[1]); close(control[1]);
        int targetExit = self ? 0 : Wait(target);
        Check(targetExit == 0, "fixture exit status");
        std::cout << "RESULT\t" << profile << '\t' << actualTarget << '\t' << actualMonitor << '\t'
            << monitorExit << '\t' << targetExit << '\t' << alive << '\n';
        return 0;
    }
    catch (const std::exception& error)
    { Cleanup(); std::cerr << error.what() << '\n'; return 1; }
}
