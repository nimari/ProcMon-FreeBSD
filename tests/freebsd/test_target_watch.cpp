// SPDX-License-Identifier: MIT
// Real sysctl/kqueue plus bounded linker-injected error/race responses; no target control.
#include "../../src/tracer/freebsd/diagnostic/target_watch.h"
#include <fcntl.h>
#include <iostream>
#include <limits>
namespace d = procmon::freebsd::diagnostic;
static unsigned checks, reads, boots;
static std::string injection;
static void Check(bool value) { ++checks; if (!value) throw std::runtime_error("watch check failed"); }
static int Descriptors()
{ int count = 0; for (int fd = 0; fd < 128; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++count; return count; }
extern "C" int __real_sysctl(const int*, u_int, void*, size_t*, const void*, size_t);
extern "C" int __real_sysctlbyname(const char*, void*, size_t*, const void*, size_t);
extern "C" int __real_kevent(int, const struct kevent*, int, struct kevent*, int, const struct timespec*);
extern "C" int __wrap_sysctl(const int* mib, u_int length, void* data, size_t* size, const void* input, size_t inputSize)
{
    if (injection == "read_error") { errno = EACCES; return -1; }
    int result = __real_sysctl(mib, length, data, size, input, inputSize);
    if (result == 0 && data && size && *size == sizeof(kinfo_proc))
    {
        ++reads;
        auto& process = *static_cast<kinfo_proc*>(data);
        if (injection == "layout") process.ki_structsize = 0;
        if (injection == "absent") *size = 0;
        if (injection == "abi") std::strcpy(process.ki_emul, "FreeBSD ELF32");
        if (injection == "zombie") process.ki_stat = SZOMB;
        if (injection == "kernel") process.ki_flag |= P_KPROC;
        if (injection == "no_identity") process.ki_paddr = nullptr;
        if (injection == "changed" && reads == 2) ++process.ki_start.tv_sec;
    }
    return result;
}
extern "C" int __wrap_sysctlbyname(const char* name, void* data, size_t* size, const void* input, size_t inputSize)
{
    if (injection == "boot_error") { errno = EIO; return -1; }
    int result = __real_sysctlbyname(name, data, size, input, inputSize);
    if (result == 0 && std::strcmp(name, "kern.boottime") == 0)
    {
        ++boots;
        if (injection == "boot_layout") --*size;
        if (injection == "boot_changed" && boots == 2) ++static_cast<timeval*>(data)->tv_sec;
    }
    return result;
}
extern "C" int __wrap_kevent(int fd, const struct kevent* changes, int count, struct kevent* events, int slots, const struct timespec* timeout)
{
    if (injection == "register_error" && count) { errno = ESRCH; return -1; }
    if (injection == "poll_error" && !count) { errno = EIO; return -1; }
    if (!count && (injection == "exit" || injection == "exec" || injection == "coalesced"))
    {
        *events = {}; events->fflags = injection == "exit" ? NOTE_EXIT : injection == "exec" ? NOTE_EXEC : NOTE_EXEC | NOTE_EXIT;
        events->data = 7 << 8; return 1;
    }
    if (!count && injection == "eintr") { injection.clear(); errno = EINTR; return -1; }
    return __real_kevent(fd, changes, count, events, slots, timeout);
}
int main()
{
    try
    {
        const int initial = Descriptors();
        for (int round = 0; round < 3; ++round)
        {
            d::TargetWatch watch; watch.Arm(getpid());
            Check(watch.identity.processAddress != 0 && watch.identity.startMicroseconds < 1000000);
            Check(watch.Poll() == d::TargetChange::None);
            bool single = false;
            try { watch.Arm(getpid()); } catch (const std::logic_error&) { single = true; }
            Check(single);
            injection = "eintr"; Check(watch.Poll() == d::TargetChange::None);
        }
        Check(Descriptors() == initial);
        for (const auto& mode : {"read_error", "layout", "absent", "abi", "zombie", "kernel", "no_identity",
            "changed", "boot_error", "boot_layout", "boot_changed", "register_error", "poll_error", "exit", "exec", "coalesced"})
        {
            injection = mode; reads = boots = 0;
            bool rejected = false;
            try { d::TargetWatch watch; watch.Arm(getpid()); }
            catch (const std::runtime_error& error) { rejected = std::string(error.what()).find("target:") == 0; }
            Check(rejected); Check(Descriptors() == initial);
        }
        injection.clear();
        for (std::uint64_t pid : {std::uint64_t(0), std::uint64_t(INT32_MAX) + 1, std::uint64_t(INT32_MAX)})
        {
            bool rejected = false;
            try { d::TargetWatch watch; watch.Arm(pid); } catch (const std::runtime_error&) { rejected = true; }
            Check(rejected);
        }
        { d::TargetWatch watch; watch.Arm(getpid());
          injection = "coalesced"; Check(watch.Poll() == d::TargetChange::Exec && watch.exitStatus == (7 << 8)); }
        injection.clear(); Check(Descriptors() == initial);
        std::cout << "PASS: " << checks << " target-watch checks\n";
    }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
