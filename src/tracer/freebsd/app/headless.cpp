// SPDX-License-Identifier: MIT
#include "../../../display/headless.h"
#include "storage.h"
#include "platform.h"
#include <thread>
#include <chrono>
#include <unistd.h>
using namespace procmon::freebsd::app;
bool Headless::initialize(std::shared_ptr<ProcmonConfiguration> configuration)
{
    config = configuration;
    std::cout << "ProcMon FreeBSD 2.2.2.1\nCAPTURE_READY monitor=" << getpid()
        << " syscalls=" << (config->events.empty() ? config->GetSchema().size() : config->events.size()) << " output=" << config->GetOutputTraceFilePath() << '\n';
    std::cout << "Ctrl-C stops capture without terminating targets.\n" << std::flush;
    return static_cast<bool>(std::cout);
}
void Headless::run()
{
    while (!applicationFinished && !stopSignal) std::this_thread::sleep_for(std::chrono::milliseconds(20));
    config->GetTracer()->Cancel();
}
void Headless::shutdown()
{
    config->GetTracer()->Cancel();
    if (!config->GetStorage()->Export({config->GetStartTime(),config->GetEpocStartTime()},config->GetOutputTraceFilePath()))
        throw std::runtime_error("cannot export FreeBSD capture");
    std::cout << "Saved " << config->GetStorage()->Size() << " events to " << config->GetOutputTraceFilePath() << '\n'
        << CaptureStatus() << '\n';
}
