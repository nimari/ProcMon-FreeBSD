/* SPDX-License-Identifier: MIT */
/* No tracing markers: wait in a parent-owned pipe read; optionally cause EFAULT. */
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <pthread_np.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 6 || getuid() == 0 || getuid() != strtoul(argv[2], NULL, 10) ||
        getgid() != strtoul(argv[3], NULL, 10)) return 2;
    int fd = atoi(argv[4]);
    if (fd < 0 || (strcmp(argv[5], "blocked") && strcmp(argv[5], "fault"))) return 2;
    alarm(8);
    if (!strcmp(argv[5], "fault"))
    {
        errno = 0;
        int result = openat(AT_FDCWD, (const char *)(uintptr_t)1, O_RDONLY);
        int error = errno;
        printf("FAULT_EXPECT\t%d\t%d\t%d\t%d\n", (int)getpid(), pthread_getthreadid_np(), result, error);
        if (result != -1 || error != EFAULT) return 1;
    }
    printf("BLOCK_EXPECT\t%d\t%d\t%d\t%u\t%u\n", (int)getpid(), pthread_getthreadid_np(), fd,
        (unsigned)getuid(), (unsigned)getgid());
    if (fflush(stdout) != 0) return 2;
    char byte;
    errno = 0;
    ssize_t result = read(fd, &byte, 1);
    int error = errno;
    printf("BLOCK_RESULT\t%d\t%d\t%zd\t%d\n", (int)getpid(), pthread_getthreadid_np(), result, error);
    return result == 1 && error == 0 ? 0 : 1;
}
