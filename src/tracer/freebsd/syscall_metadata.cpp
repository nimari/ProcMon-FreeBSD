// SPDX-License-Identifier: MIT
#include "syscall_metadata.h"

#if !defined(__FreeBSD__) || !defined(__amd64__)
#error "Native syscall metadata currently targets FreeBSD amd64 only"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <dtrace.h>
#include <sys/ctf_api.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <exception>
#include <memory>
#include <set>
#include <utility>

namespace procmon::freebsd
{
namespace
{

// Defensive metadata bound, not a six/seven-slot wire layout. Larger advertised
// counts are explicitly unavailable, never truncated or indexed unchecked.
constexpr int MaximumMetadataArguments = 64;

struct DiscoveryContext
{
    MetadataSnapshot snapshot;
    std::exception_ptr exception;
    bool incomplete = false;
};

std::string LibraryFailure(dtrace_hdl_t* handle, const char* stage)
{
    std::string message = stage;
    int error = dtrace_errno(handle);
    if (error != 0)
    {
        const char* detail = dtrace_errmsg(handle, error);
        if (detail != nullptr)
            message += std::string(": ") + detail;
    }
    return message;
}

std::optional<MetadataAttributes> CopyAttributes(const dtrace_attribute_t& source)
{
    const char* name = dtrace_stability_name(source.dtat_name);
    const char* data = dtrace_stability_name(source.dtat_data);
    const char* dependency = dtrace_class_name(source.dtat_class);
    if (name == nullptr || data == nullptr || dependency == nullptr)
        return std::nullopt;
    return MetadataAttributes{name, data, dependency};
}

int InspectProbe(dtrace_hdl_t* handle, const dtrace_probedesc_t* source,
    void* argument) noexcept
{
    auto& context = *static_cast<DiscoveryContext*>(argument);
    // Never unwind C++ exceptions through libdtrace's C callback frames.
    try
    {
        if (std::strcmp(source->dtpd_provider, "syscall") != 0 ||
            std::strcmp(source->dtpd_mod, "freebsd") != 0 ||
            (std::strcmp(source->dtpd_name, "entry") != 0 &&
             std::strcmp(source->dtpd_name, "return") != 0))
        {
            context.incomplete = true;
            context.snapshot.diagnostics.emplace_back("Unexpected probe identity during native discovery");
            return -1;
        }
        ProbeMetadata probe;
        probe.function = source->dtpd_func;
        probe.kind = std::strcmp(source->dtpd_name, "entry") == 0 ?
            ProbeKind::Entry : ProbeKind::Return;
        dtrace_probeinfo_t info{};
        if (dtrace_probe_info(handle, source, &info) != 0)
            probe.diagnostic = LibraryFailure(handle, "dtrace_probe_info failed");
        else if (info.dtp_argc < 0 || info.dtp_argc > MaximumMetadataArguments ||
            (info.dtp_argc > 0 && info.dtp_argv == nullptr))
            probe.diagnostic = "Invalid or unsupported argument metadata/count";
        else
        {
            probe.argumentCount = static_cast<std::size_t>(info.dtp_argc);
            probe.attributes = CopyAttributes(info.dtp_attr);
            probe.argumentAttributes = CopyAttributes(info.dtp_arga);
            if (!probe.attributes || !probe.argumentAttributes)
                probe.diagnostic = "Unrecognized metadata stability attributes";
            probe.arguments.reserve(*probe.argumentCount);
            for (int index = 0; index < info.dtp_argc; ++index)
            {
                ArgumentMetadata item;
                const dtrace_typeinfo_t& type = info.dtp_argv[index];
                item.userType = (type.dtt_flags & DTT_FL_USER) != 0;
                char name[512]{};
                if (type.dtt_ctfp == nullptr ||
                    ctf_type_name(type.dtt_ctfp, type.dtt_type, name, sizeof(name)) == nullptr ||
                    name[0] == '\0' || std::memchr(name, '\0', sizeof(name)) == nullptr)
                {
                    item.diagnostic = "CTF type name unavailable";
                    context.incomplete = true;
                }
                else
                    item.typeName = name;
                probe.arguments.push_back(std::move(item));
            }
        }
        if (!probe.diagnostic.empty())
            context.incomplete = true;
        context.snapshot.probes.push_back(std::move(probe));
        return 0;
    }
    catch (...)
    {
        context.exception = std::current_exception();
        return -1;
    }
}

} // namespace

MetadataSnapshot DiscoverNativeSyscallMetadata()
{
    DiscoveryContext context;
    struct stat device{};
    if (stat("/dev/dtrace/dtrace", &device) != 0)
    {
        context.snapshot.diagnostics.push_back(std::string("DTrace device unavailable: ") +
            std::strerror(errno));
        return std::move(context.snapshot);
    }
    if (!S_ISCHR(device.st_mode))
    {
        context.snapshot.diagnostics.emplace_back("DTrace device is not a character device");
        return std::move(context.snapshot);
    }
    int error = 0;
    using Handle = std::unique_ptr<dtrace_hdl_t, decltype(&dtrace_close)>;
    Handle handle(dtrace_open(DTRACE_VERSION, 0, &error), &dtrace_close);
    if (!handle)
    {
        const char* detail = dtrace_errmsg(nullptr, error);
        context.snapshot.diagnostics.push_back(std::string("dtrace_open failed: ") +
            (detail != nullptr ? detail : "unknown library error"));
        return std::move(context.snapshot);
    }
    for (const char* query : {"syscall:freebsd:*:entry", "syscall:freebsd:*:return"})
    {
        dtrace_probedesc_t filter{};
        if (dtrace_str2desc(handle.get(), DTRACE_PROBESPEC_NAME, query, &filter) != 0)
        {
            context.incomplete = true;
            context.snapshot.diagnostics.push_back(LibraryFailure(handle.get(), "Probe query failed"));
            break;
        }
        int outcome = dtrace_probe_iter(handle.get(), &filter, InspectProbe, &context);
        if (context.exception)
            std::rethrow_exception(context.exception);
        if (outcome != 0)
        {
            context.incomplete = true;
            context.snapshot.diagnostics.push_back(LibraryFailure(handle.get(), "Probe iteration failed"));
            break;
        }
    }
    // Destroy the handle before returning or inspecting the copied snapshot.
    handle.reset();
    std::sort(context.snapshot.probes.begin(), context.snapshot.probes.end(),
        [](const ProbeMetadata& left, const ProbeMetadata& right)
        {
            return left.function < right.function ||
                (left.function == right.function && left.kind < right.kind);
        });
    std::set<std::string> entries, returns;
    for (const auto& probe : context.snapshot.probes)
    {
        auto& names = probe.kind == ProbeKind::Entry ? entries : returns;
        if (!names.insert(probe.function).second)
        {
            context.incomplete = true;
            context.snapshot.diagnostics.push_back("Duplicate advertised probe: " + probe.function);
        }
    }
    if (entries.empty() || returns.empty() || entries != returns)
    {
        context.incomplete = true;
        context.snapshot.diagnostics.emplace_back("Native entry/return probe names are empty or unpaired");
    }
    context.snapshot.state = context.snapshot.probes.empty() ? MetadataState::Unavailable :
        context.incomplete ? MetadataState::Partial : MetadataState::Complete;
    return std::move(context.snapshot);
}

} // namespace procmon::freebsd
