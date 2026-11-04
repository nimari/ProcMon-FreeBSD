/* SPDX-License-Identifier: MIT */
/* Isolated clock anchors and a deliberately blocked cancellation target. */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/cpuset.h>

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <pthread_np.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define SAMPLES 8

static uint64_t
monotonic(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        perror("clock_gettime");
        exit(2);
    }
    return (uint64_t)value.tv_sec * 1000000000 + (uint64_t)value.tv_nsec;
}

static int
clock_samples(void)
{
    cpuset_t original, selected;
    int cpus[2], count = 0;
    struct timespec pause = {0, 30000000};
    if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
        sizeof(original), &original) != 0)
        return 2;
    for (int cpu = 0; cpu < CPU_SETSIZE && count < 2; cpu++) {
        if (CPU_ISSET(cpu, &original))
            cpus[count++] = cpu;
    }
    if (count == 0)
        return 2;
    for (int index = 0; index < SAMPLES; index++) {
        int cpu = cpus[index % count];
        /* Unique, nonexistent PIDs identify anchors without output-order assumptions. */
        pid_t argument = (pid_t)(-1000 - index);
        CPU_ZERO(&selected);
        CPU_SET(cpu, &selected);
        if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
            sizeof(selected), &selected) != 0)
            return 2;
        uint64_t before = monotonic();
        errno = 0;
        pid_t result = getpgid(argument);
        int error = errno;
        uint64_t after = monotonic();
        printf("CLOCK_EXPECT\t%d\t%d\t%d\t%d\t%" PRIu64 "\t%" PRIu64
            "\t%d\t%d\n", (int)getpid(), pthread_getthreadid_np(), index,
            cpu, before, after, (int)result, error);
        if (result != -1 || error == 0)
            return 1;
        nanosleep(&pause, NULL);
    }
    if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
        sizeof(original), &original) != 0)
        return 2;
    printf("CLOCK_FIXTURE\t%d\t%d\t%u\t%u\t%d\n", (int)getpid(), SAMPLES,
        (unsigned int)getuid(), (unsigned int)getgid(), count);
    return 0;
}

int
main(int argc, char **argv)
{
    char *end;
    if (argc != 5 || getuid() == 0 || getuid() != geteuid())
        return 2;
    unsigned long uid = strtoul(argv[2], &end, 10);
    if (!*argv[2] || *end || uid != (unsigned long)getuid())
        return 2;
    unsigned long gid = strtoul(argv[3], &end, 10);
    if (!*argv[3] || *end || gid != (unsigned long)getgid() || getgid() != getegid())
        return 2;
    alarm(8);
    if (strcmp(argv[4], "clock") == 0)
        return clock_samples();
    if (strcmp(argv[4], "sigint") && strcmp(argv[4], "sigterm"))
        return 2;
    int descriptors[2];
    char byte;
    if (pipe(descriptors) != 0)
        return 2;
    printf("BLOCK_EXPECT\t%d\t%d\t%d\t%u\t%u\n", (int)getpid(),
        pthread_getthreadid_np(), descriptors[0], (unsigned int)getuid(),
        (unsigned int)getgid());
    if (fflush(stdout) != 0 || getpgid(0) < 0)
        return 2;
    /* Keep the write end open so the read waits for cancellation, not EOF. */
    ssize_t result = read(descriptors[0], &byte, 1);
    fprintf(stderr, "FIXTURE_FAIL\tblocked read unexpectedly returned %zd\n", result);
    return 1;
}
