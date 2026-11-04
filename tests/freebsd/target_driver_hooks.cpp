// SPDX-License-Identifier: MIT
// Test-linked pilot only. Deterministically exit a supervised target inside go,
// or fail the watched kqueue after ready. Production has no hook/environment path.
#include <sys/event.h>
#include <dtrace.h>
#include <unistd.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
static int watchQueue = -1, polls;
extern "C" int __real_kevent(int, const struct kevent*, int, struct kevent*, int, const struct timespec*);
extern "C" int __real_dtrace_go(dtrace_hdl_t*);
extern "C" int __wrap_kevent(int fd, const struct kevent* changes, int count, struct kevent* events, int slots, const struct timespec* timeout)
{
    const char* mode = std::getenv("PROCMON_TEST_MODE");
    if (mode && count == 1 && changes->filter == EVFILT_PROC && watchQueue < 0) watchQueue = fd;
    if (mode && std::strcmp(mode, "watch_error") == 0 && fd == watchQueue && !count && ++polls == 3)
    { errno = EIO; return -1; }
    return __real_kevent(fd, changes, count, events, slots, timeout);
}
extern "C" int __wrap_dtrace_go(dtrace_hdl_t* handle)
{
    int result = __real_dtrace_go(handle);
    const char* mode = std::getenv("PROCMON_TEST_MODE");
    if (result == 0 && mode && std::strcmp(mode, "startup") == 0)
    {
        const char* target = std::getenv("PROCMON_TEST_TARGET"), *gate = std::getenv("PROCMON_TEST_GATE");
        if (!target || !gate) return -1;
        int queue = kqueue(); if (queue < 0) return -1;
        struct kevent change, event;
        EV_SET(&change, std::strtoul(target, nullptr, 10), EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, nullptr);
        const int fd = std::atoi(gate);
        bool okay = __real_kevent(queue, &change, 1, nullptr, 0, nullptr) == 0 && write(fd, "g", 1) == 1;
        const struct timespec timeout{3, 0};
        okay = okay && __real_kevent(queue, nullptr, 0, &event, 1, &timeout) == 1 && (event.fflags & NOTE_EXIT);
        close(queue); close(fd);
        if (!okay) return -1;
    }
    return result;
}
