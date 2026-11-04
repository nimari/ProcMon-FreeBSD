// SPDX-License-Identifier: MIT
#include "../../../configuration/procmon_configuration.h"
#include "../diagnostic/support.h"
#include <algorithm>
#include <iomanip>
#include <set>
#include <unistd.h>
#include <sys/stat.h>
#include <cerrno>
using namespace procmon::freebsd::app;
namespace procmon::freebsd::app { bool dumpReplay = false; }
namespace
{
std::vector<std::string> Split(const char* input)
{
    if (!input || !*input) throw std::invalid_argument("empty option value");
    std::vector<std::string> values; std::string text(input); std::size_t start = 0;
    for (;;)
    {
        auto end = text.find(',',start); auto value = text.substr(start,end == text.npos ? end : end - start);
        if (value.empty()) throw std::invalid_argument("empty comma-separated item"); values.push_back(value);
        if (end == text.npos) break; start = end + 1;
    }
    return values;
}
}
void ProcmonConfiguration::HandlePidArgs(char* input)
{
    for (const auto& value : Split(input))
    {
        auto pid = static_cast<pid_t>(procmon::freebsd::diagnostic::Positive(value,INT32_MAX));
        if (std::find(pids.begin(),pids.end(),pid) == pids.end()) pids.push_back(pid);
        if (pids.size() > MAX_PIDS) throw std::invalid_argument("at most ten PIDs may be selected");
    }
}
void ProcmonConfiguration::HandleEventArgs(char* input)
{ for (const auto& value : Split(input)) if (std::none_of(events.begin(),events.end(),[&](const auto& event) { return event.Name() == value; })) events.emplace_back(value); }
void ProcmonConfiguration::HandleStorageArgs(char* input)
{ if (!input || std::string(input) != "sql") throw std::invalid_argument("FreeBSD application supports --storageEngine sql"); }
void ProcmonConfiguration::HandleFileArg(char* input)
{ if (!input || !*input) throw std::invalid_argument("empty input trace path"); traceFilePath = input; }
void ProcmonConfiguration::HandleLogArg(char* input)
{ if (!input || !*input) throw std::invalid_argument("empty log path"); debugTraceFilePath = input; }
ProcmonConfiguration::ProcmonConfiguration(int argc,char** argv)
{
    startTime = {0,1}; epocStartTime = ConvertEpocTime(time(nullptr));
    outputTraceFilePath = "procmon_" + std::to_string(time(nullptr)) + ".db";
    static option options[] = {{"help",no_argument,nullptr,'h'}, {"pids",required_argument,nullptr,'p'},
        {"pid",required_argument,nullptr,'p'}, {"events",required_argument,nullptr,'e'}, {"collect",optional_argument,nullptr,'c'},
        {"file",required_argument,nullptr,'f'}, {"log",required_argument,nullptr,'l'}, {"storageEngine",required_argument,nullptr,'s'},
        {"duration-ms",required_argument,nullptr,1000}, {"no-strings",no_argument,nullptr,1001}, {"no-buffers",no_argument,nullptr,1002},
        {"no-stacks",no_argument,nullptr,1003}, {"list-events",no_argument,nullptr,1004}, {"dump",no_argument,nullptr,1005},
        {"version",no_argument,nullptr,1006}, {"max-events",required_argument,nullptr,1007}, {"max-bytes",required_argument,nullptr,1008}, {nullptr,0,nullptr,0}};
    bool list = false; std::set<int> seen;
    std::uint64_t maxEvents = 100000, maxBytes = 64 * 1024 * 1024;
    opterr = 0;
    for (int option; (option = getopt_long(argc,argv,"hp:e:c::f:l:s:",options,nullptr)) != -1;)
    {
        if (!seen.insert(option).second) throw std::invalid_argument("repeated command-line option");
        switch (option)
        {
            case 'h': CLIUtils::DisplayUsage(false); std::exit(0);
            case 'p': HandlePidArgs(optarg); break;
            case 'e': HandleEventArgs(optarg); break;
            case 'c': headless = true;
                if (!optarg && optind < argc && argv[optind][0] != '-') optarg = argv[optind++];
                if (optarg) { if (!*optarg) throw std::invalid_argument("empty output trace path"); outputTraceFilePath = optarg; } break;
            case 'f': HandleFileArg(optarg); break;
            case 'l': HandleLogArg(optarg); break;
            case 's': HandleStorageArgs(optarg); break;
            case 1000: durationMilliseconds = procmon::freebsd::diagnostic::Positive(optarg,86400000); break;
            case 1001: captureStrings = false; break;
            case 1002: captureBuffers = false; break;
            case 1003: captureStacks = false; break;
            case 1004: list = true; break;
            case 1005: dumpReplay = true; break;
            case 1007: maxEvents = procmon::freebsd::diagnostic::Positive(optarg,1000000); break;
            case 1008: maxBytes = procmon::freebsd::diagnostic::Positive(optarg,256 * 1024 * 1024); break;
            case 1006: std::cout << "ProcMon FreeBSD port 2.2.2.1 (native amd64)\n"; std::exit(0);
            default: throw std::invalid_argument("invalid option or missing option value; use --help");
        }
    }
    if (optind != argc) throw std::invalid_argument("unexpected positional argument");
    if ((headless && !traceFilePath.empty()) || (dumpReplay && traceFilePath.empty())) throw std::invalid_argument("--collect and --file conflict; --dump requires --file");
    if (!traceFilePath.empty() && (list || durationMilliseconds || seen.count(1007) || seen.count(1008) || seen.count(1001) || seen.count(1002) || seen.count(1003))) throw std::invalid_argument("capture options cannot be used with --file");
    if (headless)
    {
        struct stat info{};
        if (lstat(outputTraceFilePath.c_str(),&info) == 0 || errno != ENOENT)
            throw std::invalid_argument("capture output path already exists or is not accessible; choose a new file");
        auto slash = outputTraceFilePath.find_last_of('/'); auto parent = slash == outputTraceFilePath.npos ? "." : outputTraceFilePath.substr(0,slash ? slash : 1);
        if (stat(parent.c_str(),&info) || !S_ISDIR(info.st_mode) || access(parent.c_str(),W_OK | X_OK))
            throw std::invalid_argument("capture output directory is not writable");
    }
    if (traceFilePath.empty() && geteuid() != 0) throw std::runtime_error("live capture/probe discovery needs tracing privileges; use doas");
    if (traceFilePath.empty()) syscallSchema = NativeSchemas();
    for (const auto& event : events)
    {
        if (traceFilePath.empty() && std::none_of(syscallSchema.begin(),syscallSchema.end(),[&](const auto& schema) { return schema.syscallName == event.Name(); }))
            throw std::invalid_argument("unknown native FreeBSD syscall: " + event.Name());
    }
    if (list)
    {
        for (const auto& schema : syscallSchema)
        { std::cout << schema.syscallName << '('; bool first = true; for (const auto& type : schema.argumentTypes)
          { if (!first) std::cout << ", "; first = false; std::cout << type; } std::cout << ")\n"; }
        std::exit(std::cout ? 0 : 1);
    }
    _storageEngine = std::make_shared<NativeStorage>(); _storageEngine->Initialize(events);
    static_cast<NativeStorage*>(_storageEngine.get())->Limits(maxEvents,maxBytes);
    if (!traceFilePath.empty())
    { _tracerEngine = std::make_unique<ITracerEngine>(_storageEngine,events); _tracerEngine->SetRunState(TRACER_STOP); applicationFinished = true; }
    else
    { _tracerEngine = std::make_unique<NativeEngine>(_storageEngine,events,pids,syscallSchema); }
}
std::uint64_t ProcmonConfiguration::GetStartTime() { return static_cast<std::uint64_t>(startTime.tv_sec) * 1000000000 + startTime.tv_nsec; }
void ProcmonConfiguration::SetStartTime(std::uint64_t value) { startTime.tv_sec = value / 1000000000; startTime.tv_nsec = value % 1000000000; }
std::string ProcmonConfiguration::ConvertEpocTime(time_t value)
{
    std::ostringstream out; auto* utc = gmtime(&value); if (!utc) throw std::runtime_error("cannot convert capture epoch");
    out << std::put_time(utc,"%Y-%m-%dT%H:%M:%SZ"); date = out.str().substr(0,10); return out.str();
}
