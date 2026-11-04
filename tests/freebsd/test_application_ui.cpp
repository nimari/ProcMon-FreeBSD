// SPDX-License-Identifier: MIT
// Real PTY exercise. Root tests operate only on children created here.
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <libutil.h>
#include <termios.h>
#include <poll.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <unistd.h>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
static pid_t monitor = -1, target = -1;
static int master = -1, slave = -1, modesRead = -1, acknowledge = -1;
static termios restored{};
static std::string transcript;
static void Check(bool value,const char* error) { if (!value) throw std::runtime_error(error); }
static void Pump(int milliseconds)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
    do { char buffer[8192]; ssize_t count; while ((count = read(master,buffer,sizeof(buffer))) > 0) transcript.append(buffer,count);
        std::this_thread::sleep_for(std::chrono::milliseconds(10)); } while (std::chrono::steady_clock::now() < deadline);
}
static void Await(const std::string& marker)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (transcript.find(marker) == std::string::npos)
    { siginfo_t status{}; if (waitid(P_PID,monitor,&status,WEXITED | WNOHANG | WNOWAIT) == 0 && status.si_pid)
        throw std::runtime_error("PTY app exited awaiting " + marker + ": code=" + std::to_string(status.si_code) + " status=" + std::to_string(status.si_status));
       if (std::chrono::steady_clock::now() >= deadline) throw std::runtime_error("PTY output timeout: " + marker); Pump(50); }
}
static void Key(const char* keys) { Check(write(master,keys,strlen(keys)) == static_cast<ssize_t>(strlen(keys)),"PTY key"); Pump(250); }
static int Wait(pid_t& pid)
{
    if (pid == monitor)
    {
        pollfd ready{modesRead,POLLIN,0};
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        while (poll(&ready,1,0) == 0) { Check(std::chrono::steady_clock::now() < deadline,"terminal restoration timeout"); Pump(10); }
        Check(read(modesRead,&restored,sizeof(restored)) == sizeof(restored),"termios result");
        Pump(100); Check(write(acknowledge,"a",1) == 1,"terminal drain acknowledgement");
    }
    int status; const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (!waitpid(pid,&status,WNOHANG)) { Check(std::chrono::steady_clock::now() < deadline,"PTY child timeout"); Pump(50); }
    Pump(100); pid = -1; Check(WIFEXITED(status),"PTY child signalled"); return WEXITSTATUS(status);
}
int main(int argc,char** argv)
{
    std::string path;
    try
    {
        Check(argc == 5 || argc == 8,"usage: procmon database directory replay|small|resize|interrupt OR procmon fixture directory live uid gid unused");
        path = std::string(argv[3]) + "/" + argv[4] + ".pty";
        const bool live = std::string(argv[4]) == "live", small = std::string(argv[4]) == "small";
        int gate[2], control[2];
        if (live)
        {
            Check(getuid() == 0 && pipe(gate) == 0 && pipe(control) == 0,"live PTY privileges/pipes");
            target = fork(); Check(target >= 0,"PTY target fork");
            if (!target)
            {
                close(gate[1]); close(control[1]);
                int fd = open((std::string(argv[3]) + "/ui.fixture").c_str(),O_WRONLY | O_CREAT | O_TRUNC,0600); dup2(fd,1); close(fd);
                if (setgroups(0,nullptr) || setgid(std::stoul(argv[6])) || setuid(std::stoul(argv[5]))) _exit(121);
                auto g = std::to_string(gate[0]), c = std::to_string(control[0]);
                execl(argv[2],argv[2],argv[3],argv[5],argv[6],g.c_str(),c.c_str(),"block",argv[2],static_cast<char*>(nullptr)); _exit(122);
            }
            close(gate[0]); close(control[0]);
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            for (;;)
            { std::ifstream in(std::string(argv[3]) + "/ui.fixture"); std::string s((std::istreambuf_iterator<char>(in)),{});
                if (s.find("TARGET_READY") != s.npos) break;
                Check(std::chrono::steady_clock::now() < deadline,"UI target ready"); std::this_thread::sleep_for(std::chrono::milliseconds(10)); }
        }
        winsize size{}; size.ws_col = small ? 60 : 100; size.ws_row = small ? 10 : 32;
        Check(openpty(&master,&slave,nullptr,nullptr,&size) == 0,"openpty");
        termios before{}; Check(tcgetattr(slave,&before) == 0,"termios before");
        fcntl(master,F_SETFL,O_NONBLOCK);
        int modes[2], ack[2]; Check(pipe(modes) == 0 && pipe(ack) == 0,"terminal mode pipes");
        fcntl(modes[1],F_SETFD,FD_CLOEXEC); fcntl(ack[0],F_SETFD,FD_CLOEXEC);
        monitor = fork(); Check(monitor >= 0,"PTY fork");
        if (!monitor)
        {
            close(modes[0]); close(ack[1]);
            setsid(); ioctl(slave,TIOCSCTTY,0); dup2(slave,0); dup2(slave,1); dup2(slave,2); close(master); close(slave);
            // Keep the PTY session alive until restoration is observed. FreeBSD
            // revokes the slave when its session leader exits.
            auto app = fork(); if (app < 0) _exit(124);
            if (app > 0)
            {
                int status; if (waitpid(app,&status,0) != app) _exit(125);
                termios after{}; if (tcgetattr(0,&after) || write(modes[1],&after,sizeof(after)) != sizeof(after)) _exit(126);
                char byte; if (read(ack[0],&byte,1) != 1) _exit(127);
                _exit(WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status));
            }
            setenv("TERM","xterm",1); chdir(argv[3]);
            if (live)
            { close(gate[1]); close(control[1]); auto pid = std::to_string(target);
                execl(argv[1],argv[1],"-p",pid.c_str(),"-e","openat,read,write","--duration-ms","20000",static_cast<char*>(nullptr)); }
            else execl(argv[1],argv[1],"-f",argv[2],static_cast<char*>(nullptr));
            _exit(123);
        }
        close(modes[1]); close(ack[0]); modesRead = modes[0]; acknowledge = ack[1];
        if (small) { Check(Wait(monitor) == 1,"small terminal failure"); Check(transcript.find("80 columns by 24 rows") != transcript.npos,"small terminal diagnostic"); }
        else
        {
            Await("ProcessMonitor"); Pump(1200);
            if (live)
            {
                Key("\033[17~"); Await("exported:");
                Check(write(gate[1],"g",1) == 1,"release UI fixture"); Pump(200);
                Key("\033[15~"); Await("paused; unobserved");
                Key("\033[15~"); Pump(3000);
                Check(write(control[1],"c",1) == 1,"release UI read"); close(gate[1]); close(control[1]);
                Check(Wait(target) == 0,"UI target status"); Await("stopped:");
                Key("\033[17~"); Await("exported:"); Key("\033[17~");
            }
            else if (std::string(argv[4]) == "replay")
            {
                Key("\033OP"); Await("Sysinternals"); Key("\033OP");
                Key("\033OQ"); Await("Timestamp"); Key("\033OB\n");
                Key("\033OSread"); Pump(400); Key("\n"); Key("\033");
                Key("\033ORopenat"); Pump(400); Key("\033"); Pump(1200);
                Key("\033OA"); Key("\n"); Await("Event Properties"); Key("\033OB\033[6~\033OA\n");
                Key("\033[19~"); Await("Top 10 Syscall"); Key("\033[19~");
                size.ws_col = 80; size.ws_row = 24; ioctl(master,TIOCSWINSZ,&size); Pump(800);
            }
            if (std::string(argv[4]) == "resize")
            { size.ws_col = 60; size.ws_row = 10; ioctl(master,TIOCSWINSZ,&size); Check(Wait(monitor) == 1,"resize failure"); }
            else
            {
                if (std::string(argv[4]) == "interrupt") Key("\003"); else Key("q");
                Check(Wait(monitor) == 0,"PTY application status");
            }
        }
        termios after = restored; close(modes[0]); close(ack[1]);
        Check((before.c_lflag & (ICANON | ECHO | ISIG)) == (after.c_lflag & (ICANON | ECHO | ISIG)),"terminal modes restored");
        if (!small) Check(transcript.find("\033[?25h") != transcript.npos,"cursor restored");
        std::ofstream(path) << transcript;
        std::cout << "PASS: PTY " << argv[4] << " and terminal restoration\n"; close(master); close(slave);
    }
    catch (const std::exception& error)
    { if (monitor > 0) kill(-monitor,SIGKILL);
      for (auto pid : {monitor,target}) if (pid > 0) { kill(pid,SIGKILL); waitpid(pid,nullptr,0); }
        if (!path.empty()) std::ofstream(path) << transcript;
        std::cerr << error.what() << '\n'; return 1; }
}
