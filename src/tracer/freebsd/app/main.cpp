// SPDX-License-Identifier: MIT
#include "../../../configuration/procmon_configuration.h"
#include "../../../display/screen.h"
#include "../../../display/headless.h"
#include "output.h"
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <iostream>
INITIALIZE_EASYLOGGINGPP
using namespace procmon::freebsd::app;
namespace
{
void Stop(int signal) { if (!stopSignal) stopSignal = signal; }
void Signals()
{
    struct sigaction action{}; sigemptyset(&action.sa_mask); action.sa_flags = SA_RESTART; action.sa_handler = Stop;
    if (sigaction(SIGINT,&action,nullptr) || sigaction(SIGTERM,&action,nullptr)) throw std::runtime_error("cannot install stop handlers");
    action.sa_handler = SIG_IGN; if (sigaction(SIGPIPE,&action,nullptr)) throw std::runtime_error("cannot ignore SIGPIPE");
}
}
int main(int argc,char** argv)
{
    bool terminal = false;
    std::shared_ptr<ProcmonConfiguration> config;
    try
    {
        umask(077); Signals(); config = std::make_shared<ProcmonConfiguration>(argc,argv);
        if (stopSignal) return 128 + stopSignal;
        if (!config->GetDebugTraceFilePath().empty())
        {
            el::Configurations logging; logging.setToDefault();
            logging.setGlobally(el::ConfigurationType::Filename,config->GetDebugTraceFilePath());
            el::Loggers::reconfigureAllLoggers(logging);
        }
        if (dumpReplay)
        {
            auto* storage = dynamic_cast<NativeStorage*>(config->GetStorage().get());
            storage->Load(config->GetTraceFilePath()); Dump(*storage,config->pids,config->events,std::cout);
        }
        else if (config->GetHeadlessMode())
        { config->GetTracer()->Initialize(); Headless display; if (!display.initialize(config)) throw std::runtime_error("capture output failed"); display.run(); display.shutdown(); }
        else
        {
            struct winsize size{};
            if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO) || !getenv("TERM") || ioctl(STDOUT_FILENO,TIOCGWINSZ,&size) || size.ws_col < MINIMUM_WIDTH || size.ws_row < MINIMUM_HEIGHT)
                throw std::runtime_error("interactive mode needs a terminal at least 80 columns by 24 rows; use --collect or --file FILE --dump");
            config->GetTracer()->Initialize();
            Screen display; terminal = true; display.initScreen(config); display.run(); display.shutdownScreen(); terminal = false;
        }
        config->GetTracer()->Cancel();
        if (applicationFailed) { std::cerr << CaptureStatus() << '\n'; return 1; }
        return stopSignal ? 128 + stopSignal : 0;
    }
    catch (const std::exception& error)
    {
        if (config) config->GetTracer()->Cancel();
        if (terminal) { curs_set(1); endwin(); }
        std::cerr << "procmon: " << error.what() << '\n';
        return dynamic_cast<const std::invalid_argument*>(&error) ? 2 : 1;
    }
}
