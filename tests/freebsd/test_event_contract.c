/* SPDX-License-Identifier: MIT */
/* Portable boundary checks for the experimental time/status contract. */
#include <stdio.h>

#include "event_contract.h"

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL: line %d: %s\n", __LINE__, #condition); return 1; \
} } while (0)

int
main(void)
{
    struct experiment_session session = {1, EXP_DTRACE_SESSION_NS, 1000, 2000};
    struct experiment_input input = {42, 43, 1100, 50, 0, 7, EXP_READ, 1, 1, 0};
    struct experiment_event event;
    CHECK(experiment_normalize(&session, &input, &event) == 0);
    CHECK(event.state == EXP_COMPLETED && event.timestamp_ns == 100);
    CHECK(event.timestamp_valid && event.duration_valid && event.result_valid && event.errno_valid);
    CHECK(event.duration_ns == 50 && event.result == 7 && event.error == 0);

    input.raw_result = -42;
    CHECK(experiment_normalize(&session, &input, &event) == 0);
    CHECK(event.state == EXP_COMPLETED && event.result == -42 && event.error == 0);
    input.raw_result = -1;
    input.raw_errno = 9;
    CHECK(experiment_normalize(&session, &input, &event) == 0);
    CHECK(event.state == EXP_COMPLETED && event.result == -1 && event.error == 9);

    input.raw_errno = UINT64_MAX;
    input.cancellation_requested = 1;
    CHECK(experiment_normalize(&session, &input, &event) == 0);
    CHECK(event.state == EXP_CANCELLED && event.timestamp_valid);
    CHECK(!event.duration_valid && !event.result_valid && !event.errno_valid);
    CHECK(event.duration_ns == 0 && event.result == 0 && event.error == 0);
    CHECK(event.return_present && event.raw_errno == UINT64_MAX && event.raw_result == -1);

    input.return_present = 0;
    CHECK(experiment_normalize(&session, &input, &event) == 0);
    CHECK(event.state == EXP_CANCELLED && !event.return_present && event.raw_errno == 0);
    input.cancellation_requested = 0;
    CHECK(experiment_normalize(&session, &input, &event) == 0);
    CHECK(event.state == EXP_INCOMPLETE && !event.result_valid);

    input.entry_present = 0;
    input.return_present = 1;
    input.cancellation_requested = 1;
    CHECK(experiment_normalize(&session, &input, &event) == 0);
    CHECK(event.state == EXP_INCOMPLETE && !event.timestamp_valid && !event.entry_present);

    input.entry_present = 1;
    input.raw_errno = 0;
    input.raw_result = 8;
    CHECK(experiment_normalize(&session, &input, &event) == 0);
    CHECK(event.state == EXP_COMPLETED && event.result == 8);
    input.start_ns = 999;
    CHECK(experiment_normalize(&session, &input, &event) == -1);
    input.start_ns = 2001;
    CHECK(experiment_normalize(&session, &input, &event) == -1);
    input.start_ns = 1100;
    input.duration_ns = UINT64_MAX;
    CHECK(experiment_normalize(&session, &input, &event) == -1);
    input.duration_ns = 50;
    session.clock = 0;
    CHECK(experiment_normalize(&session, &input, &event) == -1);
    session.clock = EXP_DTRACE_SESSION_NS;
    session.version = 2;
    CHECK(experiment_normalize(&session, &input, &event) == -1);
    session.version = 1;
    session.end_ns = 999;
    CHECK(experiment_normalize(&session, &input, &event) == -1);
    puts("PASS: event contract validity, signed results, cancellation, missing data, and time bounds");
    return 0;
}
