// SPDX-License-Identifier: MIT
// Full application supervisor: only owned fixture PIDs are traced or signalled.
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
#include <vector>

using Clock = std::chrono::steady_clock;
static pid_t target = -1, monitor = -1;
static void Check(bool value, const char* message)
{ if (!value) throw std::runtime_error(message); }
static std::string Read(const std::string& path)
{ std::ifstream in(path); return {std::istreambuf_iterator<char>(in), {}}; }
static void Await(const std::string& path, const char* text)
{
    auto deadline = Clock::now() + std::chrono::seconds(40);
    while (Read(path).find(text) == std::string::npos)
    {
        if (monitor > 0)
        { siginfo_t info{}; if (waitid(P_PID,monitor,&info,WEXITED | WNOHANG | WNOWAIT) == 0 && info.si_pid)
            throw std::runtime_error("application exited before expected output"); }
        Check(Clock::now() < deadline, "output wait timeout");
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}
static int Wait(pid_t& child)
{
    int status = 0;
    auto deadline = Clock::now() + std::chrono::seconds(40);
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
        Check(argc == 8 && getuid() == 0, "usage: pilot native-fixture compat-fixture dir uid gid profile (as root)");
        signal(SIGPIPE,SIG_IGN);
        const std::string pilot = argv[1], fixture = argv[2], compat = argv[3], directory = argv[4], profile = argv[7];
        const auto uid = static_cast<uid_t>(std::stoul(argv[5]));
        const auto gid = static_cast<gid_t>(std::stoul(argv[6]));
        const bool self = profile == "self", broken = profile == "broken";
        const bool rejected = profile == "compat" || profile == "zombie";
        const bool exec = profile == "exec_native" || profile == "exec_compat";
        const bool killed = profile == "killed";
        const bool startup = false, watchError = false;
        const bool blocking = profile == "cancel" || profile == "term" || profile == "fault" || broken || exec || killed || watchError;
        Check(self || blocking || profile == "all" || profile == "core" || profile == "read" || profile == "write" || profile == "openat" || profile == "exit7" || profile == "limit" || profile == "byte-limit" || profile == "no-extras" || rejected, "profile");
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
                const auto gateFd = std::to_string(gate[0]), controlFd = std::to_string(control[0]);
                if (profile == "zombie") _exit(0);
                const auto& binary = profile == "compat" ? compat : fixture;
                const char* mode = rejected ? "reject" : exec ? "exec" : profile == "fault" ? "fault" : blocking ? "block" : profile == "exit7" ? "exit7" : "oracle";
                const auto& destination = profile == "exec_compat" ? compat : fixture;
                execl(binary.c_str(), binary.c_str(), fixtureDirectory.c_str(), argv[5], argv[6], gateFd.c_str(), controlFd.c_str(), mode, destination.c_str(), static_cast<char*>(nullptr));
                _exit(123);
            }
        }
        if (profile == "zombie")
        { siginfo_t info{}; Check(waitid(P_PID, target, &info, WEXITED | WNOWAIT) == 0, "retain zombie"); }
        else if (!self) Await(prefix + ".fixture", "TARGET_READY");
        close(gate[0]); close(control[0]);
        int outputPipe[2] = {-1, -1};
        if (broken) Check(pipe(outputPipe) == 0, "broken output pipe");
        monitor = fork(); Check(monitor >= 0, "monitor fork");
        if (monitor == 0)
        {
            if (!startup) close(gate[1]);
            close(control[1]);
            Redirect(prefix + ".stderr", STDERR_FILENO);
            if (broken)
            { close(outputPipe[0]); if (dup2(outputPipe[1], STDOUT_FILENO) < 0) _exit(124); close(outputPipe[1]); }
            else Redirect(prefix + ".stdout", STDOUT_FILENO);
            const auto pid = std::to_string(self ? getpid() : target);
            if (startup || watchError)
            {
                const auto fd = std::to_string(gate[1]);
                if (setenv("PROCMON_TEST_MODE", profile.c_str(), 1) || setenv("PROCMON_TEST_TARGET", pid.c_str(), 1) ||
                    setenv("PROCMON_TEST_GATE", fd.c_str(), 1)) _exit(126);
            }
            const auto database = prefix + ".db";
            std::vector<std::string> arguments{pilot, "--pid", pid, "--collect", database, "--duration-ms", self ? "100" : "10000"};
            if (profile == "read" || profile == "write" || profile == "openat")
            { arguments.push_back("--events"); arguments.push_back(profile); }
            if (profile == "core") { arguments.push_back("--events"); arguments.push_back("openat,read,write"); }
            if (profile != "all" && profile != "core" && profile != "read" && profile != "write" && profile != "openat")
            { arguments.push_back("--events"); arguments.push_back("openat,read,write"); }
            if (profile == "limit") { arguments.push_back("--max-events"); arguments.push_back("1"); }
            if (profile == "byte-limit") { arguments.push_back("--max-bytes"); arguments.push_back("1"); }
            if (profile == "no-extras") for (auto option : {"--no-strings","--no-buffers","--no-stacks"}) arguments.push_back(option);
            std::vector<char*> pointers; for (auto& argument : arguments) pointers.push_back(argument.data()); pointers.push_back(nullptr);
            execv(pilot.c_str(), pointers.data());
            _exit(125);
        }
        const auto actualMonitor = monitor, actualTarget = self ? monitor : target;
        if (broken) { close(outputPipe[0]); close(outputPipe[1]); }
        else if (!rejected && !startup) Await(prefix + ".stdout", "CAPTURE_READY");
        if (!self && !broken && !rejected && !startup) Check(write(gate[1], "g", 1) == 1, "release target");
        if (blocking && !broken)
        {
            Await(prefix + ".fixture", "BLOCK_EXPECT");
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
            if (killed) Check(kill(target, SIGTERM) == 0, "terminate owned test target");
            else if (profile == "cancel" || profile == "term" || profile == "fault") Check(kill(monitor, profile == "term" ? SIGTERM : SIGINT) == 0, "signal driver");
        }
        int monitorExit = Wait(monitor);
        int expected = profile == "cancel" ? 130 : profile == "term" ? 143 : profile == "fault" || profile == "limit" || profile == "byte-limit" || broken || rejected || exec || startup || watchError ? 1 : 0;
        Check(monitorExit == expected, "driver exit status");
        bool alive = false;
        if (blocking && !killed)
        {
            alive = kill(target, 0) == 0; Check(alive, "target survived capture closure");
            if (broken) Check(write(gate[1], "g", 1) == 1, "release after output failure");
            Check(write(control[1], "c", 1) == 1, "release blocked read");
        }
        if (profile == "compat") Check(write(gate[1], "g", 1) == 1, "release rejected target");
        close(gate[1]); close(control[1]);
        int targetExit = 0;
        if (killed)
        { int status; Check(waitpid(target, &status, 0) == target && WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM, "owned target signal status"); target = -1; targetExit = 128 + SIGTERM; }
        else targetExit = self ? 0 : Wait(target);
        Check(targetExit == (killed ? 143 : profile == "exit7" ? 7 : 0), "fixture exit status");
        std::cout << "RESULT\t" << profile << '\t' << actualTarget << '\t' << actualMonitor << '\t'
            << monitorExit << '\t' << targetExit << '\t' << alive << '\n';
        return 0;
    }
    catch (const std::exception& error)
    { Cleanup(); std::cerr << error.what() << '\n'; return 1; }
}
