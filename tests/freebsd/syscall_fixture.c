/* SPDX-License-Identifier: MIT */
/* Controlled native syscalls and independent userspace expectations. */
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <pthread_np.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define WORKERS 2
#define RECORDS 8

struct record {
    const char *operation;
    int64_t a0;
    uint64_t a2;
    int64_t result;
    int error;
    const char *path;
};

struct worker {
    int slot;
    int tid;
    int pipefd[2];
    int failures;
    unsigned int count;
    char path[PATH_MAX];
    char missing[PATH_MAX];
    struct record records[RECORDS];
};

static pthread_barrier_t start_barrier;
static pthread_barrier_t read_barrier;

static void
fatal(const char *message)
{
    fprintf(stderr, "FIXTURE_FAIL\t%s\n", message);
    exit(2);
}

static unsigned long
identity(const char *text)
{
    char *end;
    unsigned long value;

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno || !*text || *end || *text == '-' || value > UINT_MAX)
        fatal("invalid uid/gid");
    return value;
}

static void
barrier(pthread_barrier_t *value)
{
    int result = pthread_barrier_wait(value);
    if (result != 0 && result != PTHREAD_BARRIER_SERIAL_THREAD)
        fatal("pthread_barrier_wait");
}

static void
record_call(struct worker *worker, const char *operation, int64_t a0,
    uint64_t a2, int64_t result, int error, const char *path,
    int64_t expected_result, int expected_error)
{
    if (worker->count == RECORDS)
        fatal("record capacity");
    worker->records[worker->count++] = (struct record){
        operation, a0, a2, result, error, path
    };
    if (result != expected_result || error != expected_error)
        worker->failures++;
}

static void *
run_worker(void *argument)
{
    struct worker *worker = argument;
    static const char payload[] = "procmon!";
    char buffer[sizeof(payload)] = {0};
    ssize_t result;
    int fd, error;
    const int flags = O_CREAT | O_EXCL | O_RDWR;

    worker->tid = pthread_getthreadid_np();
    barrier(&start_barrier);

    errno = 0;
    fd = openat(AT_FDCWD, worker->path, flags, 0600);
    error = errno;
    record_call(worker, "openat", AT_FDCWD, flags, fd, error, worker->path,
        fd >= 0 ? fd : 0, 0);

    errno = 0;
    result = write(fd, payload, sizeof(payload) - 1);
    error = errno;
    record_call(worker, "write", fd, sizeof(payload) - 1, result, error,
        "-", sizeof(payload) - 1, 0);

    if (lseek(fd, 0, SEEK_SET) != 0)
        worker->failures++;
    errno = 0;
    result = read(fd, buffer, sizeof(payload) - 1);
    error = errno;
    record_call(worker, "read", fd, sizeof(payload) - 1, result, error,
        "-", sizeof(payload) - 1, 0);
    if (memcmp(buffer, payload, sizeof(payload) - 1) != 0)
        worker->failures++;

    errno = 0;
    result = read(-1, buffer, 1);
    error = errno;
    record_call(worker, "read", -1, 1, result, error, "-", -1, EBADF);

    errno = 0;
    result = write(-1, payload, 1);
    error = errno;
    record_call(worker, "write", -1, 1, result, error, "-", -1, EBADF);

    errno = 0;
    result = openat(AT_FDCWD, worker->missing, O_RDONLY);
    error = errno;
    record_call(worker, "openat", AT_FDCWD, O_RDONLY, result, error,
        worker->missing, -1, ENOENT);
    if (result >= 0)
        close((int)result);
    if (fd >= 0 && close(fd) != 0)
        worker->failures++;
    if (unlink(worker->path) != 0)
        worker->failures++;

    /* Both workers enter blocking reads while the main thread sleeps. */
    barrier(&read_barrier);
    errno = 0;
    result = read(worker->pipefd[0], buffer, 1);
    error = errno;
    record_call(worker, "read", worker->pipefd[0], 1, result, error,
        "-", 1, 0);
    return NULL;
}

static void
print_records(const struct worker *worker)
{
    for (unsigned int index = 0; index < worker->count; index++) {
        const struct record *item = &worker->records[index];
        printf("EXPECT\t%d\t%d\t%s\t%u\t%" PRId64 "\t%" PRIu64
            "\t%" PRId64 "\t%d\t%s\n", (int)getpid(), worker->tid,
            item->operation, index, item->a0, item->a2, item->result,
            item->error, item->path);
    }
}

int
main(int argc, char **argv)
{
    struct worker workers[WORKERS] = {0};
    struct worker main_records = {0};
    pthread_t threads[WORKERS];
    uid_t uid;
    gid_t gid;
    struct timespec delay = {0, 50000000};
    int failures = 0;

    if (argc != 4)
        fatal("usage: syscall_fixture private-directory nonroot-uid gid");
    uid = (uid_t)identity(argv[2]);
    gid = (gid_t)identity(argv[3]);
    if (uid == 0)
        fatal("workload must run as a nonroot uid");
    if (geteuid() == 0) {
        if (setgroups(0, NULL) || setgid(gid) || setuid(uid))
            fatal("drop privileges");
    }
    if (getuid() != uid || geteuid() != uid || getgid() != gid ||
        getegid() != gid)
        fatal("unexpected workload identity");

    alarm(8);
    if (pthread_barrier_init(&start_barrier, NULL, WORKERS + 1) ||
        pthread_barrier_init(&read_barrier, NULL, WORKERS + 1))
        fatal("pthread_barrier_init");
    main_records.tid = pthread_getthreadid_np();
    for (int index = 0; index < WORKERS; index++) {
        struct worker *worker = &workers[index];
        int length;

        worker->slot = index;
        length = snprintf(worker->path, sizeof(worker->path),
            "%s/procmon-smoke-worker-%d-%090d", argv[1], index, index);
        if (length < 0 || (size_t)length >= sizeof(worker->path))
            fatal("workload path too long");
        length = snprintf(worker->missing, sizeof(worker->missing),
            "%s-missing", worker->path);
        if (length < 0 || (size_t)length >= sizeof(worker->missing))
            fatal("missing path too long");
        if (pipe(worker->pipefd) ||
            pthread_create(&threads[index], NULL, run_worker, worker))
            fatal("pipe or pthread_create");
    }

    if (getpgid(0) < 0)
        fatal("start marker");
    barrier(&start_barrier);
    barrier(&read_barrier);
    while (nanosleep(&delay, &delay) < 0) {
        if (errno != EINTR)
            fatal("nanosleep");
    }
    for (int index = 0; index < WORKERS; index++) {
        errno = 0;
        ssize_t result = write(workers[index].pipefd[1], "x", 1);
        int error = errno;
        record_call(&main_records, "write", workers[index].pipefd[1], 1,
            result, error, "-", 1, 0);
    }
    for (int index = 0; index < WORKERS; index++) {
        if (pthread_join(threads[index], NULL))
            fatal("pthread_join");
        if (close(workers[index].pipefd[0]) ||
            close(workers[index].pipefd[1]))
            failures++;
        failures += workers[index].failures;
    }
    failures += main_records.failures;
    if (getpgid(getpid()) < 0)
        fatal("stop marker");
    alarm(0);

    printf("IDENTITY\t%d\t%u\t%u\n", (int)getpid(),
        (unsigned int)getuid(), (unsigned int)getgid());
    print_records(&main_records);
    for (int index = 0; index < WORKERS; index++)
        print_records(&workers[index]);
    printf("FIXTURE\t%d\t16\t%d\n", (int)getpid(), failures);
    pthread_barrier_destroy(&read_barrier);
    pthread_barrier_destroy(&start_barrier);
    return failures ? 1 : 0;
}
