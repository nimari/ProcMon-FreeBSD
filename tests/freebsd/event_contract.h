/* SPDX-License-Identifier: MIT */
/* Experimental in-memory contract; not a ProcMon API or serialized file ABI. */
#ifndef PROCMON_EXPERIMENT_EVENT_CONTRACT_H
#define PROCMON_EXPERIMENT_EVENT_CONTRACT_H

#include <stdint.h>
#include <string.h>

enum experiment_state { EXP_COMPLETED, EXP_CANCELLED, EXP_INCOMPLETE };
enum experiment_operation { EXP_OPENAT = 1, EXP_READ, EXP_WRITE };
enum experiment_clock { EXP_DTRACE_SESSION_NS = 1 };

struct experiment_session {
    uint32_t version;
    enum experiment_clock clock;
    uint64_t start_ns, end_ns;
};

struct experiment_input {
    uint64_t pid, tid, start_ns, duration_ns, raw_errno;
    int64_t raw_result;
    enum experiment_operation operation;
    int entry_present, return_present, cancellation_requested;
};

struct experiment_event {
    uint32_t version;
    uint64_t pid, tid;
    enum experiment_operation operation;
    enum experiment_state state;
    int timestamp_valid, duration_valid, result_valid, errno_valid;
    uint64_t timestamp_ns, duration_ns;
    int64_t result;
    uint32_t error;
    int entry_present, return_present;
    int64_t raw_result;
    uint64_t raw_errno;
};

/* Reject a mixed/invalid domain before subtracting, avoiding unsigned wrap. */
static inline int
experiment_normalize(const struct experiment_session *session,
    const struct experiment_input *input, struct experiment_event *event)
{
    if (session->version != 1 || session->clock != EXP_DTRACE_SESSION_NS ||
        session->end_ns < session->start_ns || input->pid == 0 || input->tid == 0 ||
        input->operation < EXP_OPENAT || input->operation > EXP_WRITE ||
        (input->entry_present != 0 && input->entry_present != 1) ||
        (input->return_present != 0 && input->return_present != 1) ||
        (input->cancellation_requested != 0 && input->cancellation_requested != 1))
        return -1;
    memset(event, 0, sizeof(*event));
    event->version = 1;
    event->pid = input->pid;
    event->tid = input->tid;
    event->operation = input->operation;
    event->entry_present = input->entry_present;
    event->return_present = input->return_present;
    event->raw_result = input->return_present ? input->raw_result : 0;
    event->raw_errno = input->return_present ? input->raw_errno : 0;
    event->state = EXP_INCOMPLETE;
    /* A return alone does not justify inventing an entry or entry timestamp. */
    if (!input->entry_present)
        return 0;
    if (input->start_ns < session->start_ns || input->start_ns > session->end_ns)
        return -1;
    event->timestamp_valid = 1;
    event->timestamp_ns = input->start_ns - session->start_ns;
    if (input->return_present && input->raw_errno <= INT32_MAX) {
        /* Subtract first: start + duration could overflow before comparison. */
        if (input->duration_ns > session->end_ns - input->start_ns)
            return -1;
        event->state = EXP_COMPLETED;
        event->duration_valid = event->result_valid = event->errno_valid = 1;
        event->duration_ns = input->duration_ns;
        event->result = input->raw_result;
        event->error = (uint32_t)input->raw_errno;
    } else if (input->cancellation_requested)
        event->state = EXP_CANCELLED;
    return 0;
}

#endif
