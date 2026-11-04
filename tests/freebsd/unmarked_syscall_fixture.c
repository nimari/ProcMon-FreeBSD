/* SPDX-License-Identifier: MIT */
/* Independent six-call oracle; no tracing-control markers. */
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <pthread_np.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct expectation {
    const char *operation, *path;
    int64_t descriptor, result;
    uint64_t third;
    int error;
};
int main(int argc, char **argv)
{
    struct expectation records[6];
    char path[PATH_MAX], missing[PATH_MAX], buffer[8] = {0};
    const char payload[] = "unmarked";
    int fd, error, failures = 0;
    ssize_t result;
    if (argc != 4 || getuid() == 0 || getuid() != strtoul(argv[2], NULL, 10) ||
        getgid() != strtoul(argv[3], NULL, 10)) return 2;
    alarm(8);
    if (snprintf(path, sizeof(path), "%s/unmarked-file-000000000000000000000000000000000000000000000000000000000000000000000000", argv[1]) >= (int)sizeof(path) ||
        snprintf(missing, sizeof(missing), "%s-missing", path) >= (int)sizeof(missing)) return 2;
    errno = 0;
    fd = openat(AT_FDCWD, path, O_CREAT | O_EXCL | O_RDWR, 0600); error = errno;
    records[0] = (struct expectation){"openat", path, AT_FDCWD, fd, O_CREAT | O_EXCL | O_RDWR, error};
    failures += fd < 0 || error != 0;
    errno = 0;
    result = write(fd, payload, 8); error = errno;
    records[1] = (struct expectation){"write", "-", fd, result, 8, error};
    failures += result != 8 || error != 0;
    failures += lseek(fd, 0, SEEK_SET) != 0;
    errno = 0;
    result = read(fd, buffer, 8); error = errno;
    records[2] = (struct expectation){"read", "-", fd, result, 8, error};
    failures += result != 8 || error != 0 || memcmp(buffer, payload, 8) != 0;
    errno = 0;
    result = read(-1, buffer, 1); error = errno;
    records[3] = (struct expectation){"read", "-", -1, result, 1, error};
    failures += result != -1 || error != EBADF;
    errno = 0;
    result = write(-1, payload, 1); error = errno;
    records[4] = (struct expectation){"write", "-", -1, result, 1, error};
    failures += result != -1 || error != EBADF;
    errno = 0;
    result = openat(AT_FDCWD, missing, O_RDONLY); error = errno;
    records[5] = (struct expectation){"openat", missing, AT_FDCWD, result, O_RDONLY, error};
    failures += result != -1 || error != ENOENT;
    if (fd >= 0) failures += close(fd) != 0;
    failures += unlink(path) != 0;
    printf("IDENTITY\t%d\t%u\t%u\n", (int)getpid(), (unsigned)getuid(), (unsigned)getgid());
    for (unsigned int index = 0; index < 6; ++index)
        printf("EXPECT\t%d\t%d\t%s\t%u\t%" PRId64 "\t%" PRIu64 "\t%" PRId64 "\t%d\t%s\n",
            (int)getpid(), pthread_getthreadid_np(), records[index].operation, index,
            records[index].descriptor, records[index].third, records[index].result,
            records[index].error, records[index].path);
    printf("FIXTURE\t%d\t6\t%d\n", (int)getpid(), failures);
    return failures ? 1 : 0;
}
