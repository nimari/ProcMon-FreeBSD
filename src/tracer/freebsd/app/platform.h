// SPDX-License-Identifier: MIT
#pragma once
#include "event.h"
#include <atomic>
#include <string>
#include <vector>
#include <signal.h>
#define MAX_PIDS 10
#define TRACER_RUNNING 0
#define TRACER_SUSPENDED 1
#define TRACER_STOP 2
struct SyscallSchema
{
    std::string syscallName;
    std::vector<std::string> argumentTypes;
};
namespace procmon::freebsd::app
{
extern volatile sig_atomic_t stopSignal;
extern std::atomic<bool> applicationFinished;
extern std::atomic<bool> applicationFailed;
extern std::uint64_t durationMilliseconds;
extern bool captureStrings, captureBuffers, captureStacks;
extern bool dumpReplay;
std::string CaptureStatus();
void SetCaptureStatus(const std::string& status);
}
