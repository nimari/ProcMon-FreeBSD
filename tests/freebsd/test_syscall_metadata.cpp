// SPDX-License-Identifier: MIT
// Native contract check. Linker wrappers inject metadata failures only in this
// test executable; the component has no test modes or environment switches.
#include "../../src/tracer/freebsd/syscall_metadata.h"

#include <sys/types.h>
#include <dtrace.h>
#include <sys/ctf_api.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <new>
#include <sstream>
#include <stdexcept>
#include <string>

using namespace procmon::freebsd;

namespace
{
std::string mode;
unsigned int opened, closed, injected;
bool sendfileEntry;
unsigned int argumentIndex;

void Require(bool condition, const char* message)
{
    if (!condition)
        throw std::runtime_error(message);
}

const ProbeMetadata& SendfileEntry(const MetadataSnapshot& snapshot)
{
    auto found = std::find_if(snapshot.probes.begin(), snapshot.probes.end(),
        [](const ProbeMetadata& probe)
        { return probe.function == "sendfile" && probe.kind == ProbeKind::Entry; });
    Require(found != snapshot.probes.end(), "sendfile entry missing");
    return *found;
}

std::string Inventory(const MetadataSnapshot& snapshot)
{
    std::ostringstream output;
    for (const auto& probe : snapshot.probes)
    {
        Require(probe.argumentCount && probe.attributes && probe.argumentAttributes &&
            probe.diagnostic.empty(), "unavailable probe metadata in complete snapshot");
        Require(*probe.argumentCount == probe.arguments.size(), "argument count mismatch");
        const char* kind = probe.kind == ProbeKind::Entry ? "entry" : "return";
        const auto& names = *probe.attributes;
        const auto& args = *probe.argumentAttributes;
        output << "PROBE\t" << kind << '\t' << probe.function << '\t' << *probe.argumentCount
               << '\t' << names.nameStability << '\t' << names.dataStability
               << '\t' << names.dependencyClass << '\t' << args.nameStability
               << '\t' << args.dataStability << '\t' << args.dependencyClass << '\n';
        for (std::size_t index = 0; index < probe.arguments.size(); ++index)
        {
            const auto& arg = probe.arguments[index];
            Require(arg.typeName && !arg.typeName->empty() && arg.diagnostic.empty(),
                "unavailable argument in complete snapshot");
            output << "ARG\t" << kind << '\t' << probe.function << '\t' << index
                   << '\t' << arg.userType << '\t' << *arg.typeName << '\n';
        }
    }
    return output.str();
}
} // namespace

extern "C"
{
dtrace_hdl_t* __real_dtrace_open(int, int, int*);
void __real_dtrace_close(dtrace_hdl_t*);
int __real_dtrace_probe_info(dtrace_hdl_t*, const dtrace_probedesc_t*, dtrace_probeinfo_t*);
char* __real_ctf_type_name(ctf_file_t*, ctf_id_t, char*, std::size_t);

dtrace_hdl_t* __wrap_dtrace_open(int version, int flags, int* error)
{
    auto* handle = __real_dtrace_open(version, flags, error);
    if (handle != nullptr)
        ++opened;
    return handle;
}

void __wrap_dtrace_close(dtrace_hdl_t* handle)
{
    ++closed;
    __real_dtrace_close(handle);
}

int __wrap_dtrace_probe_info(dtrace_hdl_t* handle, const dtrace_probedesc_t* probe,
    dtrace_probeinfo_t* info)
{
    sendfileEntry = std::strcmp(probe->dtpd_func, "sendfile") == 0 &&
        std::strcmp(probe->dtpd_name, "entry") == 0;
    argumentIndex = 0;
    if (sendfileEntry && mode == "info-failure")
    {
        ++injected;
        return -1;
    }
    int result = __real_dtrace_probe_info(handle, probe, info);
    if (result == 0 && sendfileEntry)
    {
        if (mode == "large-count" || mode == "negative-count" || mode == "null-arguments")
        {
            ++injected;
            if (mode == "large-count")
                info->dtp_argc = 65;
            else if (mode == "negative-count")
                info->dtp_argc = -1;
            else
            {
                info->dtp_argc = 7;
                info->dtp_argv = nullptr;
            }
        }
    }
    return result;
}

char* __wrap_ctf_type_name(ctf_file_t* file, ctf_id_t type, char* buffer, std::size_t size)
{
    if (sendfileEntry && argumentIndex++ == 6 &&
        (mode == "type-failure" || mode == "callback-exception"))
    {
        ++injected;
        if (mode == "callback-exception")
            throw std::bad_alloc();
        return nullptr;
    }
    return __real_ctf_type_name(file, type, buffer, size);
}
} // extern "C"

int main(int argc, char** argv)
{
    try
    {
        Require(argc == 2, "usage: test_syscall_metadata normal|denied|info-failure|type-failure|large-count|negative-count|null-arguments|callback-exception");
        mode = argv[1];
        Require(mode == "normal" || mode == "denied" || mode == "info-failure" ||
            mode == "type-failure" || mode == "large-count" || mode == "negative-count" ||
            mode == "null-arguments" || mode == "callback-exception", "unknown test mode");
        if (mode == "callback-exception")
        {
            for (int attempt = 0; attempt < 2; ++attempt)
            {
                bool caught = false;
                try { (void)DiscoverNativeSyscallMetadata(); }
                catch (const std::bad_alloc&) { caught = true; }
                Require(caught, "callback exception swallowed");
            }
            Require(opened == 2 && closed == 2 && injected == 2,
                "callback exception cleanup failed");
            std::cout << "METADATA_TEST\tmode=" << mode
                      << "\tprobes=0\topens=2\tcloses=2\tinjected=2\tpassed=1\n";
            return std::cout.good() ? 0 : 1;
        }
        auto first = DiscoverNativeSyscallMetadata();
        auto second = DiscoverNativeSyscallMetadata();
        Require(opened == closed, "library handle leak");
        if (mode == "denied")
        {
            Require(opened == 0 && injected == 0, "denied case unexpectedly opened a handle");
            Require(first.state == MetadataState::Unavailable && first.probes.empty() &&
                !first.diagnostics.empty() && second.state == MetadataState::Unavailable &&
                second.probes.empty() && !second.diagnostics.empty(), "missing unavailable diagnostics");
            std::cout << "UNAVAILABLE\t" << first.diagnostics.front() << '\n';
        }
        else
        {
            Require(opened == 2 && !first.probes.empty() &&
                first.probes.size() == second.probes.size(), "repeated discovery incomplete");
            if (mode == "normal")
            {
                Require(injected == 0 && first.state == MetadataState::Complete &&
                    second.state == MetadataState::Complete && first.diagnostics.empty() &&
                    second.diagnostics.empty(), "normal discovery is not complete");
                auto firstText = Inventory(first);
                Require(firstText == Inventory(second), "owned snapshot changed after reopening library");
                Require(SendfileEntry(first).arguments.size() == 7 &&
                    *SendfileEntry(first).arguments[6].typeName == "int", "seventh argument lost");
                // A caller can alter its copy after closure without changing another snapshot.
                auto copy = first;
                copy.probes.front().function = "changed-test-copy";
                Require(Inventory(first) == firstText && Inventory(second) == firstText,
                    "snapshot ownership violated");
                std::cout << firstText;
            }
            else
            {
                Require(injected == 2 && first.state == MetadataState::Partial &&
                    second.state == MetadataState::Partial, "injected failure reported as complete");
                for (const auto* snapshot : {&first, &second})
                {
                    const auto& probe = SendfileEntry(*snapshot);
                    unsigned int failures = 0;
                    for (const auto& item : snapshot->probes)
                    {
                        failures += !item.diagnostic.empty();
                        for (const auto& arg : item.arguments)
                            failures += !arg.diagnostic.empty();
                    }
                    Require(snapshot->diagnostics.empty() && failures == 1,
                        "failure not isolated to requested metadata");
                    if (mode == "type-failure")
                    {
                        Require(probe.argumentCount == 7 && probe.arguments.size() == 7 &&
                            !probe.arguments[6].typeName && !probe.arguments[6].diagnostic.empty(),
                            "missing seventh type was fabricated/truncated");
                        for (std::size_t index = 0; index < 6; ++index)
                            Require(probe.arguments[index].typeName.has_value(), "unrelated type lost");
                    }
                    else
                        Require(!probe.argumentCount && probe.arguments.empty() &&
                            !probe.diagnostic.empty(), "unavailable query/count presented as zero");
                }
            }
        }
        std::cout << "METADATA_TEST\tmode=" << mode << "\tprobes=" << first.probes.size()
                  << "\topens=" << opened << "\tcloses=" << closed
                  << "\tinjected=" << injected << "\tpassed=1\n";
        return std::cout.good() ? 0 : 1;
    }
    catch (const std::exception& error)
    {
        std::cerr << "METADATA_TEST_FAILURE\t" << error.what() << '\n';
        return 1;
    }
}
