/* SPDX-License-Identifier: MIT */
/* Standalone API experiment. No ProcMon dependencies or dtrace subprocess. */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <dtrace.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "event_contract.h"

#define CONTRACT_CAPACITY 32

struct contract_pending {
    struct experiment_input input;
    int64_t a0;
    uint64_t a2;
    char path[65];
};

struct context {
    pid_t child;
    uint64_t probes, records, zero_records, entries, returns, errors, drops;
    int bad_schema, started, stopped, drained, closed, reaped;
    int startup_error, child_status;
    int mode, blocked, signal_sent, signal_seen;
    uint64_t cancel_start_ns, cancel_elapsed_ns;
    int contract, contract_begin, contract_end, contract_count;
    uint64_t contract_start_ns, contract_end_ns;
    struct contract_pending pending[CONTRACT_CAPACITY];
    int stack_enabled;
    uint64_t stack_samples, stack_frames;
};

static volatile sig_atomic_t interrupted;

static void
on_signal(int signal_number)
{
    interrupted = signal_number;
}

static int
on_error(const dtrace_errdata_t *data, void *argument)
{
    struct context *context = argument;
    context->errors++;
    fprintf(stderr, "API_ERROR\tfault=%d\t%s", data->dteda_fault,
        data->dteda_msg);
    return DTRACE_HANDLE_OK;
}

static int
on_drop(const dtrace_dropdata_t *data, void *argument)
{
    struct context *context = argument;
    context->drops += data->dtdda_drops;
    fprintf(stderr, "API_DROP\tkind=%d\tcount=%" PRIu64 "\t%s",
        data->dtdda_kind, data->dtdda_drops, data->dtdda_msg);
    return DTRACE_HANDLE_OK;
}

/* Validate the public record descriptors before reading any payload bytes. */
static int
decode(const dtrace_probedata_t *data, int scalars, int has_path,
    uint64_t *values, char *path)
{
    const dtrace_eprobedesc_t *description = data->dtpda_edesc;
    int field = 0;
    for (int index = 0; index < description->dtepd_nrecs; index++) {
        const dtrace_recdesc_t *record = &description->dtepd_rec[index];
        if (record->dtrd_action != DTRACEACT_DIFEXPR ||
            record->dtrd_offset > description->dtepd_size)
            return -1;
        /* Assignments have descriptors but carry no data field. */
        if (record->dtrd_size == 0)
            continue;
        uint32_t wanted = field < scalars ? sizeof(uint64_t) : 65;
        if (field >= scalars + has_path ||
            record->dtrd_size != wanted ||
            wanted > description->dtepd_size - record->dtrd_offset)
            return -1;
        const char *payload = data->dtpda_data + record->dtrd_offset;
        if (field < scalars)
            memcpy(&values[field], payload, sizeof(values[field]));
        else {
            if (memchr(payload, '\0', 65) == NULL)
                return -1;
            memcpy(path, payload, 65);
        }
        field++;
    }
    return field == scalars + has_path ? 0 : -1;
}

static const char *
operation_name(enum experiment_operation operation)
{
    return operation == EXP_OPENAT ? "openat" : operation == EXP_READ ? "read" : "write";
}

static struct contract_pending *
pending_call(struct context *context, uint64_t pid, uint64_t tid,
    uint64_t start, enum experiment_operation operation)
{
    for (int index = 0; index < context->contract_count; index++) {
        struct experiment_input *input = &context->pending[index].input;
        if (input->pid == pid && input->tid == tid && input->start_ns == start &&
            input->operation == operation)
            return &context->pending[index];
    }
    if (context->contract_count == CONTRACT_CAPACITY)
        return NULL;
    struct contract_pending *slot = &context->pending[context->contract_count++];
    slot->input.pid = pid;
    slot->input.tid = tid;
    slot->input.start_ns = start;
    slot->input.operation = operation;
    return slot;
}

static int
on_contract_probe(const dtrace_probedata_t *data, struct context *context)
{
    const dtrace_probedesc_t *probe = data->dtpda_pdesc;
    uint64_t value[8] = {0};
    char path[65];
    int entry = strcmp(probe->dtpd_name, "entry") == 0;
    const char *function = probe->dtpd_func;
    if (strcmp(probe->dtpd_provider, "dtrace") == 0) {
        if (decode(data, 2, 0, value, path))
            goto bad;
        if (strcmp(probe->dtpd_name, "BEGIN") == 0 && !context->contract_begin) {
            context->contract_begin = 1;
            context->contract_start_ns = value[1];
            printf("BEGIN\t%" PRIu64 "\n", value[0]);
        } else if (strcmp(probe->dtpd_name, "END") == 0 && !context->contract_end) {
            context->contract_end = 1;
            context->contract_end_ns = value[1];
            puts("END");
        } else
            goto bad;
    } else if (strcmp(probe->dtpd_provider, "syscall") != 0 ||
        strcmp(probe->dtpd_mod, "freebsd") != 0)
        goto bad;
    else if (strcmp(function, "getpgid") == 0 && entry) {
        if (decode(data, 3, 0, value, path) || (value[2] != 0 && value[2] != value[0]))
            goto bad;
        printf("%s\t%" PRIu64 "\t%" PRIu64 "\n",
            value[2] == 0 ? "START" : "STOP", value[0], value[1]);
    } else if (strcmp(function, "_exit") == 0 && entry) {
        if (decode(data, 2, 0, value, path))
            goto bad;
        printf("TARGET_EXIT\t%" PRIu64 "\t%" PRIu64 "\n", value[0], value[1]);
    } else {
        enum experiment_operation operation = strcmp(function, "openat") == 0 ?
            EXP_OPENAT : strcmp(function, "read") == 0 ? EXP_READ :
            strcmp(function, "write") == 0 ? EXP_WRITE : 0;
        if (!operation || (!entry && strcmp(probe->dtpd_name, "return")) ||
            decode(data, entry ? 5 : 8, 1, value, path) || !value[1])
            goto bad;
        struct contract_pending *slot = pending_call(context, value[0], value[1],
            value[2], operation);
        if (slot == NULL || (entry ? slot->input.entry_present : slot->input.return_present))
            goto bad;
        int64_t a0 = (int64_t)value[entry ? 3 : 6];
        uint64_t a2 = value[entry ? 4 : 7];
        if ((slot->input.entry_present || slot->input.return_present) &&
            (slot->a0 != a0 || slot->a2 != a2 || strcmp(slot->path, path)))
            goto bad;
        slot->a0 = a0;
        slot->a2 = a2;
        memcpy(slot->path, path, sizeof(slot->path));
        if (entry) {
            slot->input.entry_present = 1;
            context->entries++;
            if (context->mode >= 4)
                context->blocked++;
            printf("RAW_ENTRY\t%" PRIu64 "\t%" PRIu64 "\t%s\t%" PRIu64
                "\t%" PRId64 "\t%" PRIu64 "\t%s\n", value[0], value[1],
                function, value[2], a0, a2, path);
        } else {
            slot->input.return_present = 1;
            slot->input.duration_ns = value[3];
            slot->input.raw_result = (int64_t)value[4];
            slot->input.raw_errno = value[5];
            context->returns++;
            printf("RAW_RETURN\t%" PRIu64 "\t%" PRIu64 "\t%s\t%" PRIu64
                "\t%" PRIu64 "\t%" PRId64 "\t%" PRIu64 "\t%" PRId64
                "\t%" PRIu64 "\t%s\n", value[0], value[1], function,
                value[2], value[3], (int64_t)value[4], value[5], a0, a2, path);
        }
    }
    if (value[0] != (uint64_t)context->child || ferror(stdout))
        goto bad;
    return DTRACE_CONSUME_THIS;
bad:
    context->bad_schema++;
    fprintf(stderr, "CONTRACT_FAILURE\tunexpected record or bounded collector capacity\n");
    return DTRACE_CONSUME_ABORT;
}

/* Emit only after the final drain, using owned data rather than callback pointers. */
static int
finish_contract(struct context *context)
{
    unsigned int counts[3] = {0};
    if (!context->contract_begin || !context->contract_end ||
        context->contract_end_ns < context->contract_start_ns)
        return -1;
    struct experiment_session session = {1, EXP_DTRACE_SESSION_NS,
        context->contract_start_ns, context->contract_end_ns};
    printf("SESSION\t1\tfreebsd-native\tdtrace-session-ns\t%d\t%" PRIu64
        "\t%" PRIu64 "\n", (int)context->child, session.start_ns, session.end_ns);
    for (int index = 0; index < context->contract_count; index++) {
        struct experiment_input *input = &context->pending[index].input;
        struct experiment_event event;
        input->cancellation_requested = context->signal_seen != 0;
        if (experiment_normalize(&session, input, &event) != 0)
            return -1;
        counts[event.state]++;
        const char *state = event.state == EXP_COMPLETED ? "completed" :
            event.state == EXP_CANCELLED ? "cancelled" : "incomplete";
        printf("CONTRACT_EVENT\t%u\t%" PRIu64 "\t%" PRIu64 "\t%s\t%s"
            "\t%d\t%" PRIu64 "\t%d\t%" PRIu64 "\t%d\t%" PRId64
            "\t%d\t%u\t%d\t%d\t%" PRId64 "\t%" PRIu64 "\n",
            event.version, event.pid, event.tid, operation_name(event.operation),
            state, event.timestamp_valid, event.timestamp_ns, event.duration_valid,
            event.duration_ns, event.result_valid, event.result, event.errno_valid,
            event.error, event.entry_present, event.return_present, event.raw_result,
            event.raw_errno);
    }
    printf("CONTRACT_COUNTS\t%u\t%u\t%u\n", counts[EXP_COMPLETED],
        counts[EXP_CANCELLED], counts[EXP_INCOMPLETE]);
    return counts[EXP_INCOMPLETE] || ferror(stdout) ? -1 : 0;
}

static int
on_stack_probe(const dtrace_probedata_t *data, struct context *context)
{
    const dtrace_eprobedesc_t *description = data->dtpda_edesc;
    uint64_t values[3], stack[9];
    if (description->dtepd_nrecs != 4)
        goto bad;
    for (int index = 0; index < 4; index++) {
        const dtrace_recdesc_t *record = &description->dtepd_rec[index];
        uint32_t wanted = index < 3 ? sizeof(uint64_t) : sizeof(stack);
        if (record->dtrd_action != (index < 3 ? DTRACEACT_DIFEXPR : DTRACEACT_USTACK) ||
            record->dtrd_size != wanted || record->dtrd_offset > description->dtepd_size ||
            wanted > description->dtepd_size - record->dtrd_offset)
            goto bad;
        if (index < 3)
            memcpy(&values[index], data->dtpda_data + record->dtrd_offset, wanted);
        else {
            if (DTRACE_USTACK_NFRAMES(record->dtrd_arg) != 8 ||
                DTRACE_USTACK_STRSIZE(record->dtrd_arg) != 0)
                goto bad;
            memcpy(stack, data->dtpda_data + record->dtrd_offset, wanted);
        }
    }
    if (values[0] != (uint64_t)context->child || stack[0] != values[0] || !values[1])
        goto bad;
    unsigned int nonzero = 0;
    for (int index = 1; index <= 8; index++)
        nonzero += stack[index] != 0;
    if (!nonzero)
        goto bad;
    context->entries++;
    context->stack_samples++;
    context->stack_frames += nonzero;
    printf("STACK\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t8\t%u",
        values[0], values[1], values[2], nonzero);
    for (int index = 1; index <= 8; index++)
        printf("\t0x%" PRIx64, stack[index]);
    putchar('\n');
    return ferror(stdout) ? DTRACE_CONSUME_ABORT : DTRACE_CONSUME_THIS;
bad:
    context->bad_schema++;
    fprintf(stderr, "STACK_FAILURE\tinvalid bounded raw user-stack record\n");
    return DTRACE_CONSUME_ABORT;
}

static int
on_probe(const dtrace_probedata_t *data, void *argument)
{
    struct context *context = argument;
    const dtrace_probedesc_t *probe = data->dtpda_pdesc;
    uint64_t value[8] = {0};
    char path[65];
    const char *function = probe->dtpd_func;
    int entry = strcmp(probe->dtpd_name, "entry") == 0;

    context->probes++;
    if (context->contract)
        return on_contract_probe(data, context);
    if (context->stack_enabled && !strcmp(probe->dtpd_provider, "syscall") &&
        !strcmp(probe->dtpd_mod, "freebsd") && !strcmp(function, "openat") && entry)
        return on_stack_probe(data, context);
    if (strcmp(probe->dtpd_provider, "dtrace") == 0) {
        if (decode(data, 1, 0, value, path) ||
            value[0] != (uint64_t)context->child)
            goto bad;
        if (strcmp(probe->dtpd_name, "BEGIN") == 0)
            printf("BEGIN\t%" PRIu64 "\n", value[0]);
        else if (strcmp(probe->dtpd_name, "END") == 0)
            printf("END\n");
        else
            goto bad;
    } else if (strcmp(probe->dtpd_provider, "syscall") != 0 ||
        strcmp(probe->dtpd_mod, "freebsd") != 0)
        goto bad;
    else if (strcmp(function, "getpgid") == 0 && entry) {
        if (context->mode == 3) {
            if (decode(data, 4, 0, value, path))
                goto bad;
            context->entries++;
            printf("CLOCK_ENTRY\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
                "\t%" PRId64 "\t%d\n", value[0], value[1], value[2],
                (int64_t)value[3], data->dtpda_cpu);
            goto validated;
        }
        if (decode(data, 3, 0, value, path) ||
            (value[2] != 0 && value[2] != value[0]))
            goto bad;
        printf("%s\t%" PRIu64 "\t%" PRIu64 "\n",
            value[2] == 0 ? "START" : "STOP", value[0], value[1]);
    } else if (context->mode == 3 && strcmp(function, "getpgid") == 0 &&
        strcmp(probe->dtpd_name, "return") == 0) {
        if (decode(data, 6, 0, value, path))
            goto bad;
        context->returns++;
        printf("CLOCK_RETURN\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
            "\t%" PRId64 "\t%" PRIu64 "\t%" PRId64 "\t%d\n", value[0],
            value[1], value[2], (int64_t)value[3], value[4],
            (int64_t)value[5], data->dtpda_cpu);
    } else if (context->mode >= 4 && strcmp(function, "read") == 0) {
        if ((!entry && strcmp(probe->dtpd_name, "return") != 0) ||
            decode(data, 5, 0, value, path))
            goto bad;
        if (entry) {
            context->entries++;
            context->blocked++;
            printf("BLOCKED\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
                "\t%" PRId64 "\t%" PRIu64 "\n", value[0], value[1],
                value[2], (int64_t)value[3], value[4]);
        } else {
            context->returns++;
            printf("BLOCK_RETURN\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64
                "\t%" PRId64 "\t%" PRIu64 "\n", value[0], value[1],
                value[2], (int64_t)value[3], value[4]);
        }
    } else if (strcmp(function, "_exit") == 0 && entry) {
        if (decode(data, 2, 0, value, path))
            goto bad;
        printf("TARGET_EXIT\t%" PRIu64 "\t%" PRIu64 "\n",
            value[0], value[1]);
    } else if (strcmp(function, "openat") == 0 ||
        strcmp(function, "read") == 0 || strcmp(function, "write") == 0) {
        if ((!entry && strcmp(probe->dtpd_name, "return") != 0) ||
            decode(data, entry ? 5 : 8, 1, value, path))
            goto bad;
        if (entry) {
            context->entries++;
            printf("ENTRY\t%" PRIu64 "\t%" PRIu64 "\t%s\t%" PRIu64
                "\t%" PRId64 "\t%" PRIu64 "\t%s\n", value[0], value[1],
                function, value[2], (int64_t)value[3], value[4], path);
        } else {
            context->returns++;
            printf("EVENT\t%" PRIu64 "\t%" PRIu64 "\t%s\t%" PRIu64
                "\t%" PRIu64 "\t%" PRId64 "\t%" PRIu64 "\t%" PRId64
                "\t%" PRIu64 "\t%s\n", value[0], value[1], function,
                value[2], value[3], (int64_t)value[4], value[5],
                (int64_t)value[6], value[7], path);
        }
    } else
        goto bad;
validated:
    if (value[0] != (uint64_t)context->child || ferror(stdout))
        goto bad;
    return DTRACE_CONSUME_THIS;
bad:
    context->bad_schema++;
    fprintf(stderr, "API_SCHEMA\t%s:%s:%s:%s\n", probe->dtpd_provider,
        probe->dtpd_mod, function, probe->dtpd_name);
    for (int index = 0; index < data->dtpda_edesc->dtepd_nrecs; index++) {
        const dtrace_recdesc_t *record = &data->dtpda_edesc->dtepd_rec[index];
        fprintf(stderr, "API_DESCRIPTOR\tindex=%d\taction=%u\tsize=%u\toffset=%u\n",
            index, record->dtrd_action, record->dtrd_size, record->dtrd_offset);
    }
    return DTRACE_CONSUME_ABORT;
}

static int
on_record(const dtrace_probedata_t *data, const dtrace_recdesc_t *record,
    void *argument)
{
    struct context *context = argument;
    (void)data;
    if (record != NULL) {
        if (record->dtrd_size == 0)
            context->zero_records++;
        else
            context->records++;
    }
    /* Never ask libdtrace to format a payload for us. */
    return record == NULL ? DTRACE_CONSUME_THIS : DTRACE_CONSUME_NEXT;
}

static void
library_error(dtrace_hdl_t *handle, const char *operation)
{
    fprintf(stderr, "API_FAILURE\t%s\t%s\n", operation,
        dtrace_errmsg(handle, dtrace_errno(handle)));
}

static int
reap(struct context *context, int options)
{
    int status;
    pid_t result;
    do {
        result = waitpid(context->child, &status, options);
    } while (result < 0 && errno == EINTR);
    if (result == context->child) {
        context->reaped = 1;
        context->child_status = WIFEXITED(status) ? WEXITSTATUS(status) :
            128 + WTERMSIG(status);
    }
    return result < 0 ? -1 : 0;
}

int
main(int argc, char **argv)
{
    struct context context = {0};
    dtrace_hdl_t *handle = NULL;
    dtrace_prog_t *program;
    FILE *script = NULL, *status_file = NULL;
    char fixture_output[PATH_MAX], status_path[PATH_MAX], pid_text[32], mode_text[8];
    char *end, *macro_arguments[3];
    unsigned long uid_value, gid_value;
    int gate[2] = {-1, -1}, code = 1, error, mode;
    struct timespec start, now, pause = {0, 10000000};
    struct sigaction action = {.sa_handler = on_signal};
    struct sigaction ignore_pipe = {.sa_handler = SIG_IGN};
    struct stat device;

    if ((argc != 7 && argc != 8) || (argc == 8 && strcmp(argv[7], "--contract") &&
        strcmp(argv[7], "--stacks")) ||
        (strcmp(argv[6], "normal") && strcmp(argv[6], "fault") &&
        strcmp(argv[6], "drop") && strcmp(argv[6], "clock") &&
        strcmp(argv[6], "sigint") && strcmp(argv[6], "sigterm"))) {
        fprintf(stderr, "usage: libdtrace_consumer script fixture directory uid gid normal|fault|drop|clock|sigint|sigterm [--contract|--stacks]\n");
        return 2;
    }
    mode = !strcmp(argv[6], "fault") ? 1 : !strcmp(argv[6], "drop") ? 2 :
        !strcmp(argv[6], "clock") ? 3 : !strcmp(argv[6], "sigint") ? 4 :
        !strcmp(argv[6], "sigterm") ? 5 : 0;
    context.mode = mode;
    context.contract = argc == 8 && !strcmp(argv[7], "--contract");
    context.stack_enabled = argc == 8 && !strcmp(argv[7], "--stacks");
    if (context.contract && mode != 0 && mode != 4 && mode != 5)
        return 2;
    if (context.stack_enabled && mode != 0)
        return 2;
    errno = 0;
    uid_value = strtoul(argv[4], &end, 10);
    if (errno || !*argv[4] || *end || *argv[4] == '-' || uid_value == 0 ||
        uid_value > UINT_MAX)
        return 2;
    errno = 0;
    gid_value = strtoul(argv[5], &end, 10);
    if (errno || !*argv[5] || *end || *argv[5] == '-' || gid_value > UINT_MAX)
        return 2;
    if (snprintf(fixture_output, sizeof(fixture_output), "%s/fixture.tsv", argv[3])
        >= (int)sizeof(fixture_output) ||
        snprintf(status_path, sizeof(status_path), "%s/api-status.tsv", argv[3])
        >= (int)sizeof(status_path))
        return 2;
    status_file = fopen(status_path, "w");
    if (status_file == NULL || fchown(fileno(status_file), (uid_t)uid_value,
        (gid_t)gid_value) != 0) {
        perror("status file");
        if (status_file != NULL)
            fclose(status_file);
        return 1;
    }
    script = fopen(argv[1], "r");
    if (script == NULL || stat("/dev/dtrace/dtrace", &device) != 0 ||
        !S_ISCHR(device.st_mode) || pipe(gate) != 0 ||
        clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        perror("preflight");
        context.startup_error = 1;
        goto cleanup;
    }
    sigemptyset(&action.sa_mask);
    sigemptyset(&ignore_pipe.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL) ||
        sigaction(SIGPIPE, &ignore_pipe, NULL)) {
        context.startup_error = 1;
        goto cleanup;
    }
    context.child = fork();
    if (context.child < 0) {
        perror("fork");
        context.startup_error = 1;
        goto cleanup;
    }
    if (context.child == 0) {
        char token;
        close(gate[1]);
        close(fileno(script));
        close(fileno(status_file));
        if (setgroups(0, NULL) || setgid((gid_t)gid_value) ||
            setuid((uid_t)uid_value) || read(gate[0], &token, 1) != 1)
            _exit(125);
        close(gate[0]);
        int output = open(fixture_output, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (output < 0 || dup2(output, STDOUT_FILENO) < 0)
            _exit(125);
        close(output);
        char *arguments[] = {argv[2], argv[3], argv[4], argv[5],
            mode >= 3 ? argv[6] : NULL, NULL};
        execv(argv[2], arguments);
        _exit(126);
    }
    close(gate[0]);
    gate[0] = -1;
    handle = dtrace_open(DTRACE_VERSION, 0, &error);
    if (handle == NULL) {
        fprintf(stderr, "API_FAILURE\topen\t%s\n", dtrace_errmsg(NULL, error));
        context.startup_error = 1;
        goto cleanup;
    }
    if (dtrace_handle_err(handle, on_error, &context) ||
        dtrace_handle_drop(handle, on_drop, &context) ||
        dtrace_setopt(handle, "bufsize", mode == 2 ? "1k" : "4m") ||
        dtrace_setopt(handle, "dynvarsize", "4m") ||
        dtrace_setopt(handle, "switchrate", "100hz") ||
        dtrace_setopt(handle, "statusrate", "100hz")) {
        library_error(handle, "setup");
        context.startup_error = 1;
        goto cleanup;
    }
    snprintf(pid_text, sizeof(pid_text), "%d", (int)context.child);
    macro_arguments[0] = argv[1];
    macro_arguments[1] = pid_text;
    snprintf(mode_text, sizeof(mode_text), "%d", mode);
    macro_arguments[2] = mode_text;
    program = dtrace_program_fcompile(handle, script, 0, 3, macro_arguments);
    if (program == NULL || dtrace_program_exec(handle, program, NULL) != 0 ||
        dtrace_go(handle) != 0) {
        library_error(handle, "compile/enable/go");
        context.startup_error = 1;
        goto cleanup;
    }
    context.started = 1;
    if (write(gate[1], "x", 1) != 1)
        goto cleanup;
    close(gate[1]);
    gate[1] = -1;

    for (;;) {
        if ((!context.reaped && reap(&context, WNOHANG)) ||
            clock_gettime(CLOCK_MONOTONIC, &now) != 0)
            goto cleanup;
        if (mode >= 4 && context.blocked && !context.signal_sent) {
            context.signal_sent = mode == 4 ? SIGINT : SIGTERM;
            context.cancel_start_ns = (uint64_t)now.tv_sec * 1000000000 +
                (uint64_t)now.tv_nsec;
            /* Deliver a real signal only after observing this fixture's read. */
            if (kill(getpid(), context.signal_sent) != 0)
                goto cleanup;
        }
        if (interrupted) {
            context.signal_seen = interrupted;
            fprintf(stderr, "API_CANCEL\tsignal=%d\n", (int)interrupted);
            code = 128 + interrupted;
            goto cleanup;
        }
        if (now.tv_sec - start.tv_sec >= 10) {
            fprintf(stderr, "API_FAILURE\ttimeout\n");
            goto cleanup;
        }
        if ((context.reaped || context.errors || context.drops ||
            context.bad_schema) && !context.stopped) {
            if (dtrace_stop(handle) != 0) {
                library_error(handle, "stop");
                goto cleanup;
            }
            context.stopped = 1;
        }
        /* The drop case deliberately withholds consumption for this workload. */
        if (mode != 2 || context.stopped) {
            dtrace_workstatus_t result = dtrace_work(handle, NULL,
                on_probe, on_record, &context);
            if (result == DTRACE_WORKSTATUS_ERROR) {
                library_error(handle, "work");
                goto cleanup;
            }
            if (result == DTRACE_WORKSTATUS_DONE) {
                context.drained = 1;
                break;
            }
        }
        nanosleep(&pause, NULL);
    }
    code = !(context.reaped && context.child_status == 0 &&
        context.entries == (context.stack_enabled ? 4U : mode == 3 ? 8U : 16U) &&
        context.returns == (context.stack_enabled ? 0U : mode == 3 ? 8U : 16U) &&
        !context.errors && !context.drops && !context.bad_schema);

cleanup:
    if (gate[0] >= 0)
        close(gate[0]);
    if (gate[1] >= 0)
        close(gate[1]);
    if (context.child > 0 && !context.reaped) {
        kill(context.child, SIGKILL);
        if (reap(&context, 0) != 0)
            perror("waitpid");
    }
    if (handle != NULL) {
        if (context.started && !context.stopped) {
            if (dtrace_stop(handle) == 0) {
                context.stopped = 1;
                if (dtrace_work(handle, NULL, on_probe, on_record, &context) ==
                    DTRACE_WORKSTATUS_DONE)
                    context.drained = 1;
            } else
                library_error(handle, "cleanup-stop");
        }
        dtrace_close(handle);
        context.closed = 1;
    }
    if (script != NULL)
        fclose(script);
    if (context.contract && finish_contract(&context) != 0) {
        fprintf(stderr, "CONTRACT_FAILURE\tincomplete session or invalid event/time contract\n");
        code = 1;
    }
    if (context.stack_enabled)
        printf("STACK_COUNTS\t%" PRIu64 "\t%" PRIu64 "\n",
            context.stack_samples, context.stack_frames);
    if (context.cancel_start_ns != 0 &&
        clock_gettime(CLOCK_MONOTONIC, &now) == 0)
        context.cancel_elapsed_ns = (uint64_t)now.tv_sec * 1000000000 +
            (uint64_t)now.tv_nsec - context.cancel_start_ns;
    fprintf(status_file, "API_STATUS\tpid=%d\tmode=%s\tprobes=%" PRIu64
        "\trecords=%" PRIu64 "\tzero_records=%" PRIu64
        "\tentries=%" PRIu64 "\treturns=%" PRIu64
        "\terrors=%" PRIu64 "\tdrops=%" PRIu64 "\tschema=%d\tstarted=%d"
        "\tstopped=%d\tdrained=%d\tclosed=%d\treaped=%d\tchild_status=%d"
        "\tstartup_error=%d\tblocked=%d\tsignal_sent=%d\tsignal_seen=%d"
        "\tcancel_elapsed_ns=%" PRIu64 "\n", (int)context.child, argv[6], context.probes,
        context.records, context.zero_records, context.entries, context.returns, context.errors,
        context.drops, context.bad_schema, context.started, context.stopped,
        context.drained, context.closed, context.reaped, context.child_status,
        context.startup_error, context.blocked, context.signal_sent,
        context.signal_seen, context.cancel_elapsed_ns);
    if (fclose(status_file) != 0 || fflush(stdout) != 0)
        code = 1;
    return code;
}
