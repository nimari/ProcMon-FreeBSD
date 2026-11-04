// SPDX-License-Identifier: MIT
#pragma once
#include "capture.h"
#include "../../../tracer/tracer_engine.h"
#include <thread>
namespace procmon::freebsd::app
{
class NativeEngine final : public ITracerEngine
{
public:
    NativeEngine(std::shared_ptr<IStorageEngine> storage, std::vector<Event> events,
        std::vector<pid_t> pids, std::vector<SyscallSchema> schemas);
    ~NativeEngine() override;
    void Initialize() override;
    void SetRunState(int state) override;
    int GetRunState() override { return state.load(); }
    void Cancel() override;
private:
    std::vector<pid_t> pids;
    std::vector<SyscallSchema> schemas;
    std::atomic<int> state{TRACER_STOP};
    std::thread worker;
};
}
