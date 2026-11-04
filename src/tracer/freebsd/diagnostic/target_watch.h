// SPDX-License-Identifier: MIT
#pragma once
#include "../native_program.h"
#include <sys/types.h>
#include <sys/event.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>

namespace procmon::freebsd::diagnostic
{
enum class TargetChange { None, Exit, Exec };
// One watched process, never a re-opened/reused numeric PID. No process control.
// Arm before DTrace, recheck the snapshot after registration, and check again
// after tracing starts. Any exec is a conservative failure, even native-to-native.
class TargetWatch
{
public:
    ~TargetWatch() { if (queue >= 0) close(queue); }
    TargetWatch() = default;
    TargetWatch(const TargetWatch&) = delete;
    TargetWatch& operator=(const TargetWatch&) = delete;
    NativeTargetIdentity identity;
    std::optional<int> exitStatus;
    void Arm(std::uint64_t pid)
    {
        if (queue >= 0) throw std::logic_error("target watcher is single-use");
        const auto first = Snapshot(pid);
        queue = kqueue();
        if (queue < 0) Error("kqueue");
        struct kevent change;
        EV_SET(&change, pid, EVFILT_PROC, EV_ADD | EV_CLEAR, NOTE_EXIT | NOTE_EXEC, 0, nullptr);
        if (kevent(queue, &change, 1, nullptr, 0, nullptr) < 0) Error("register exit/exec watch");
        const auto second = Snapshot(pid);
        if (first.processAddress != second.processAddress || first.startSeconds != second.startSeconds ||
            first.startMicroseconds != second.startMicroseconds || Poll() != TargetChange::None)
            throw std::runtime_error("target: process changed during preflight");
        identity = second;
    }
    TargetChange Poll()
    {
        if (queue < 0) throw std::logic_error("target watcher is not armed");
        struct kevent event;
        const struct timespec zero{};
        int count;
        do { count = kevent(queue, nullptr, 0, &event, 1, &zero); } while (count < 0 && errno == EINTR);
        if (count < 0) Error("poll exit/exec watch");
        if (!count) return TargetChange::None;
        if (event.flags & EV_ERROR) throw std::runtime_error("target: exit/exec watch reported an error");
        if (event.fflags & NOTE_EXIT) exitStatus = static_cast<int>(event.data);
        // Exec wins when events coalesce; an ABI transition cannot be success.
        if (event.fflags & NOTE_EXEC) return TargetChange::Exec;
        if (event.fflags & NOTE_EXIT) return TargetChange::Exit;
        throw std::runtime_error("target: unexpected exit/exec notification");
    }
private:
    int queue = -1;
    [[noreturn]] static void Error(const char* stage)
    { const int error = errno; throw std::runtime_error(std::string("target: ") + stage + ": " + std::strerror(error)); }
    static timeval Boot()
    {
        timeval value{}; std::size_t size = sizeof(value);
        if (sysctlbyname("kern.boottime", &value, &size, nullptr, 0) < 0) Error("read boot time");
        if (size != sizeof(value)) throw std::runtime_error("target: unexpected boot-time layout");
        return value;
    }
    static NativeTargetIdentity Snapshot(std::uint64_t pid)
    {
        if (!pid || pid > INT32_MAX) throw std::runtime_error("target: invalid native PID");
        const auto boot = Boot();
        int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, static_cast<int>(pid)};
        kinfo_proc process{}; std::size_t size = sizeof(process);
        if (sysctl(mib, 4, &process, &size, nullptr, 0) < 0) Error("read process");
        if (!size) throw std::runtime_error("target: process does not exist or is not visible");
        if (size != sizeof(process) || process.ki_structsize != sizeof(process) || process.ki_pid != static_cast<int>(pid))
            throw std::runtime_error("target: unexpected process layout/identity");
        if (process.ki_stat == SZOMB || (process.ki_flag & P_KPROC))
            throw std::runtime_error("target: zombie or kernel process is unsupported");
        if (std::strncmp(process.ki_emul, "FreeBSD ELF64", sizeof(process.ki_emul)) != 0)
            throw std::runtime_error("target: requires native FreeBSD ELF64 ABI");
        const auto after = Boot();
        if (boot.tv_sec != after.tv_sec || boot.tv_usec != after.tv_usec)
            throw std::runtime_error("target: boot-time adjustment during snapshot; retry");
        auto seconds = process.ki_start.tv_sec - boot.tv_sec;
        auto microseconds = process.ki_start.tv_usec - boot.tv_usec;
        if (microseconds < 0) { --seconds; microseconds += 1000000; }
        if (!process.ki_paddr || seconds < 0 || microseconds < 0 || microseconds >= 1000000)
            throw std::runtime_error("target: kernel process identity is unavailable");
        return {reinterpret_cast<std::uintptr_t>(process.ki_paddr), static_cast<std::uint64_t>(seconds),
            static_cast<std::uint64_t>(microseconds)};
    }
};
} // namespace procmon::freebsd::diagnostic
