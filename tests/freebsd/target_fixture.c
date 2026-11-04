/* SPDX-License-Identifier: MIT */
/* Already-execed, unprivileged fixture. Gate/control descriptors belong to tests. */
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <pthread_np.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct expectation { const char *operation, *path; int64_t fd, result; uint64_t third; int error; };
int main(int argc, char **argv)
{
    if (argc != 8 || getuid() == 0 || getuid() != strtoul(argv[2], NULL, 10) ||
        getgid() != strtoul(argv[3], NULL, 10)) return 2;
    const int gate = atoi(argv[4]), control = atoi(argv[5]);
    const char *mode = argv[6];
    const int pid = (int)getpid(), tid = pthread_getthreadid_np();
#ifndef PROCMON_APP_FIXTURE_TIMEOUT
#define PROCMON_APP_FIXTURE_TIMEOUT 10
#endif
    alarm(PROCMON_APP_FIXTURE_TIMEOUT);
    if (strcmp(mode, "afterexec"))
    {
        printf("TARGET_READY\t%d\t%d\t%u\t%u\n", pid, tid, (unsigned)getuid(), (unsigned)getgid());
        if (fflush(stdout)) return 2;
        char byte;
        if (read(gate, &byte, 1) != 1) return 2;
        close(gate);
    }
    if (!strcmp(mode, "exec"))
    {
        execl(argv[7], argv[7], argv[1], argv[2], argv[3], "-1", argv[5], "afterexec", argv[7], (char *)NULL);
        return 2;
    }
    if (!strcmp(mode, "reject")) return 0;
    if (!strcmp(mode, "fault"))
    {
        errno = 0;
        int result = openat(AT_FDCWD, (const char *)(uintptr_t)1, O_RDONLY), error = errno;
        printf("FAULT_EXPECT\t%d\t%d\t%d\t%d\n", pid, tid, result, error);
        if (result != -1 || error != EFAULT) return 1;
    }
    if (!strcmp(mode, "block") || !strcmp(mode, "fault") || !strcmp(mode, "afterexec"))
    {
        printf("BLOCK_EXPECT\t%d\t%d\t%d\t%u\t%u\n", pid, tid, control, (unsigned)getuid(), (unsigned)getgid());
        if (!strcmp(mode, "afterexec")) printf("AFTER_EXEC\t%d\t%zu\n", pid, sizeof(void *));
        if (fflush(stdout)) return 2;
        char byte; errno = 0;
        ssize_t result = read(control, &byte, 1); int error = errno;
        printf("BLOCK_RESULT\t%d\t%d\t%zd\t%d\n", pid, tid, result, error);
        return result == 1 && error == 0 ? 0 : 1;
    }
    struct expectation records[6];
    char path[1024], missing[1024], buffer[8];
    const char payload[] = "native64";
    if (snprintf(path, sizeof(path), "%s/q\"back\\slash-000000000000000000000000000000000000000000000000000000000000000000000", argv[1]) >= (int)sizeof(path) ||
        snprintf(missing, sizeof(missing), "%s-missing", path) >= (int)sizeof(missing)) return 2;
    errno = 0;
    int fd = openat(AT_FDCWD, path, O_CREAT | O_EXCL | O_RDWR, 0600), error = errno;
    records[0] = (struct expectation){"openat", path, AT_FDCWD, fd, O_CREAT | O_EXCL | O_RDWR, error};
    int failures = fd < 0 || error != 0;
    errno = 0;
    ssize_t result = write(fd, payload, 8); error = errno;
    records[1] = (struct expectation){"write", "-", fd, result, 8, error}; failures += result != 8 || error != 0;
    failures += lseek(fd, 0, SEEK_SET) != 0;
    errno = 0;
    result = read(fd, buffer, 8); error = errno;
    records[2] = (struct expectation){"read", "-", fd, result, 8, error}; failures += result != 8 || error != 0 || memcmp(buffer, payload, 8);
    errno = 0;
    result = read(-1, buffer, 1); error = errno;
    records[3] = (struct expectation){"read", "-", -1, result, 1, error}; failures += result != -1 || error != EBADF;
    errno = 0;
    result = write(-1, payload, 1); error = errno;
    records[4] = (struct expectation){"write", "-", -1, result, 1, error}; failures += result != -1 || error != EBADF;
    errno = 0;
    result = openat(AT_FDCWD, missing, O_RDONLY); error = errno;
    records[5] = (struct expectation){"openat", missing, AT_FDCWD, result, O_RDONLY, error}; failures += result != -1 || error != ENOENT;
    if (fd >= 0) failures += close(fd) != 0;
    failures += unlink(path) != 0;
    for (unsigned index = 0; index < 6; ++index)
        printf("EXPECT\t%d\t%d\t%s\t%u\t%" PRId64 "\t%" PRIu64 "\t%" PRId64 "\t%d\t%s\n", pid, tid,
            records[index].operation, index, records[index].fd, records[index].third, records[index].result, records[index].error, records[index].path);
    printf("FIXTURE\t%d\t6\t%d\n", pid, failures);
    return failures ? 1 : !strcmp(mode, "exit7") ? 7 : 0;
}
