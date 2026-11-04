// SPDX-License-Identifier: MIT
#include "capture.h"
#include "../syscall_metadata.h"
#include <dtrace.h>
#include <unistd.h>
#include <algorithm>
#include <cstring>
#include <locale>
#include <set>
#include <sstream>
#include <stdexcept>

namespace procmon::freebsd::app
{
namespace
{
constexpr std::uint64_t Protocol = 0x504d0002;
bool NoReturn(const std::string& name) { return name == "_exit" || name == "thr_exit"; }
bool Identifier(const std::string& name)
{
    if (name.empty() || name.size() >= 100) return false;
    if (name[0] == '#') return name.size() > 1 && std::all_of(name.begin() + 1,name.end(),[](unsigned char c) { return std::isdigit(c); });
    return (std::isalpha(static_cast<unsigned char>(name[0])) || name[0] == '_') &&
        std::all_of(name.begin(), name.end(), [](unsigned char c) { return std::isalnum(c) || c == '_' || c == '.'; });
}
std::vector<unsigned> Paths(const std::string& name)
{
    static const std::map<std::string,std::vector<unsigned>> paths = {
        {"open",{0}}, {"openat",{1}}, {"stat",{0}}, {"lstat",{0}}, {"fstatat",{1}},
        {"chdir",{0}}, {"chroot",{0}}, {"unlink",{0}}, {"unlinkat",{1}}, {"mkdir",{0}}, {"mkdirat",{1}},
        {"rmdir",{0}}, {"rename",{0,1}}, {"renameat",{1,3}}, {"readlink",{0}}, {"readlinkat",{1}},
        {"link",{0,1}}, {"linkat",{1,3}}, {"symlink",{0,1}}, {"symlinkat",{0,2}},
        {"access",{0}}, {"faccessat",{1}}, {"chmod",{0}}, {"fchmodat",{1}}, {"chown",{0}},
        {"lchown",{0}}, {"fchownat",{1}}, {"execve",{0}}, {"mknod",{0}}, {"mknodat",{1}},
        {"truncate",{0}}, {"lchmod",{0}}, {"pathconf",{0}}, {"mount",{0,1}}, {"unmount",{0}},
        {"chflags",{0}}, {"lchflags",{0}}, {"utimes",{0}}, {"lutimes",{0}}, {"statfs",{0}}
    };
    auto found = paths.find(name); return found == paths.end() ? std::vector<unsigned>{} : found->second;
}
bool InputBuffer(const std::string& name) { return name == "write" || name == "pwrite" || name == "sendto" || name == "connect" || name == "bind"; }
bool OutputBuffer(const std::string& name) { return name == "read" || name == "pread" || name == "recvfrom"; }
unsigned ExtraCount(const SyscallSchema& schema, const CaptureOptions& options, bool entry, bool returned)
{
    unsigned count = 0;
    if (entry && options.strings) for (auto index : Paths(schema.syscallName)) if (index < schema.argumentTypes.size()) ++count;
    if (options.buffers && schema.argumentTypes.size() >= 3 &&
        ((entry && InputBuffer(schema.syscallName)) || (returned && OutputBuffer(schema.syscallName)))) ++count;
    return count;
}
std::string ArgumentName(const std::string& syscall, unsigned index)
{
    static const std::map<std::string,std::vector<std::string>> names = {
        {"openat",{"dirfd","path","flags","mode"}}, {"open",{"path","flags","mode"}},
        {"read",{"fd","buffer","count"}}, {"write",{"fd","buffer","count"}}, {"close",{"fd"}},
        {"pread",{"fd","buffer","count","offset"}}, {"pwrite",{"fd","buffer","count","offset"}},
        {"socket",{"domain","type","protocol"}}, {"connect",{"fd","address","length"}},
        {"bind",{"fd","address","length"}}, {"listen",{"fd","backlog"}}, {"kill",{"pid","signal"}},
        {"mmap",{"address","length","protection","flags","fd","offset"}}, {"execve",{"path","argv","envp"}}
    };
    auto found = names.find(syscall);
    return found != names.end() && index < found->second.size() ? found->second[index] : "arg" + std::to_string(index);
}
void Trace(std::ostringstream& source, const std::string& expression) { source << "trace((uint64_t)(" << expression << "));\n"; }
void Head(std::ostringstream& source, unsigned kind)
{ Trace(source, std::to_string(Protocol)); Trace(source, std::to_string(kind)); Trace(source,"pid"); Trace(source,"tid"); Trace(source,"self->pm_start"); }
std::int64_t Signed(std::uint64_t bits) { std::int64_t value; std::memcpy(&value, &bits, 8); return value; }
}
std::vector<SyscallSchema> NativeSchemas()
{
    const auto metadata = DiscoverNativeSyscallMetadata();
    if (metadata.state == MetadataState::Unavailable) throw std::runtime_error("native syscall metadata unavailable; load the DTrace syscall provider and check privileges");
    std::vector<SyscallSchema> result;
    for (const auto& probe : metadata.probes)
    {
        if (probe.kind != ProbeKind::Entry) continue;
        if (!Identifier(probe.function) || !probe.argumentCount || *probe.argumentCount > 8 || probe.arguments.size() != *probe.argumentCount)
            throw std::runtime_error("unsupported native metadata: " + probe.function);
        SyscallSchema schema; schema.syscallName = probe.function;
        for (const auto& argument : probe.arguments)
        { if (!argument.typeName) throw std::runtime_error("unresolved native argument metadata: " + probe.function);
          schema.argumentTypes.push_back(*argument.typeName); }
        result.push_back(std::move(schema));
    }
    if (result.empty()) throw std::runtime_error("no native FreeBSD syscall probes available");
    std::sort(result.begin(), result.end(), [](const auto& a, const auto& b) { return a.syscallName < b.syscallName; });
    return result;
}
std::string ApplicationProgram(const CaptureOptions& options, std::uint64_t monitorPid)
{
    if (!monitorPid || monitorPid > INT32_MAX || options.schemas.empty() || options.schemas.size() > 1024 || options.targets.size() > 10)
        throw std::runtime_error("invalid native application capture configuration");
    std::ostringstream source; source.imbue(std::locale::classic());
    source << "#pragma D option strsize=257\n";
    source << "dtrace:::BEGIN {"; Trace(source,std::to_string(Protocol)); Trace(source,"0"); Trace(source,"timestamp"); source << "}\n";
    std::string predicate = "pid != " + std::to_string(monitorPid) + " && curthread->td_proc->p_sysent != 0 && stringof(curthread->td_proc->p_sysent->sv_name) == \"FreeBSD ELF64\"";
    if (!options.targets.empty())
    {
        predicate += " && ("; bool first = true;
        for (const auto& target : options.targets)
        {
            if (!target.pid || target.pid > INT32_MAX || !target.identity.processAddress || target.identity.startMicroseconds >= 1000000)
                throw std::runtime_error("invalid application target identity");
            if (!first) predicate += " || "; first = false;
            predicate += "(pid == " + std::to_string(target.pid) + " && (uint64_t)curthread->td_proc == " + std::to_string(target.identity.processAddress) +
                "ULL && curthread->td_proc->p_stats->p_start.tv_sec == " + std::to_string(target.identity.startSeconds) +
                "LL && curthread->td_proc->p_stats->p_start.tv_usec == " + std::to_string(target.identity.startMicroseconds) + ")";
        }
        predicate += ')';
    }
    std::set<std::string> emitted;
    for (const auto& schema : options.schemas)
        if (!Identifier(schema.syscallName) || schema.argumentTypes.size() > 8 || !emitted.insert(schema.syscallName).second)
            throw std::runtime_error("invalid/duplicate syscall schema");
    if (!options.allSyscalls)
    {
        predicate += " && ("; bool first = true;
        for (const auto& name : emitted)
        { if (!first) predicate += " || "; first = false; predicate += "probefunc == \"" + name + "\""; }
        predicate += ')';
    }
    // One native entry/return pair covers the catalog, including reserved and
    // compatibility names. Runtime sy_narg must match the discovered CTF schema;
    // unused lanes are zero, and the decoder never drops a seventh argument.
    source << "syscall:freebsd::entry\n/" << predicate << "/\n{ self->pm_seen = 1; self->pm_start = timestamp;\n"
        << "self->pm_count = curthread->td_sa.callp->sy_narg;\n";
    for (unsigned i = 0; i < 8; ++i)
        source << "self->pm_a" << i << " = self->pm_count > " << i << " ? arg" << i << " : 0;\n";
    Head(source,1); Trace(source,"uid"); Trace(source,"gid"); Trace(source,"self->pm_count");
    Trace(source,"curthread->td_proc->p_stats->p_start.tv_sec"); Trace(source,"curthread->td_proc->p_stats->p_start.tv_usec");
    Trace(source,"(uint64_t)curthread->td_proc->p_textvp");
    for (unsigned i = 0; i < 8; ++i) Trace(source,"self->pm_a" + std::to_string(i));
    source << "trace(execname);\n"; if (options.stacks) source << "ustack(16);\n"; source << "}\n";
    for (const auto& schema : options.schemas)
    {
        const auto& name = schema.syscallName; const auto count = schema.argumentTypes.size();
        const auto selected = predicate + " && probefunc == \"" + name + "\"";
        if (options.strings) for (auto index : Paths(name)) if (index < count)
        { source << "syscall:freebsd:" << name << ":entry\n/" << selected << "/\n{"; Head(source,3); Trace(source,std::to_string(index));
          source << "trace(copyinstr(self->pm_a" << index << ", 256));}\n"; }
        if (options.buffers && count >= 3 && InputBuffer(name))
        {
            source << "syscall:freebsd:" << name << ":entry\n/" << selected << " && self->pm_a2 > 0/\n{";
            Head(source,4); Trace(source,"1"); Trace(source,"self->pm_a2 < 32 ? self->pm_a2 : 32");
            source << "tracemem(copyin(self->pm_a1, self->pm_a2 < 32 ? self->pm_a2 : 32), 32, self->pm_a2 < 32 ? self->pm_a2 : 32);}\n";
            source << "syscall:freebsd:" << name << ":entry\n/" << selected << " && self->pm_a2 == 0/\n{";
            Head(source,5); Trace(source,"1"); source << "}\n";
        }
        if (options.buffers && count >= 3 && OutputBuffer(name))
        {
            source << "syscall:freebsd:" << name << ":return\n/" << selected << " && self->pm_seen && errno == 0 && (int64_t)arg0 > 0/\n{";
            Head(source,4); Trace(source,"1"); Trace(source,"arg0 < 32 ? arg0 : 32");
            source << "tracemem(copyin(self->pm_a1, arg0 < 32 ? arg0 : 32), 32, arg0 < 32 ? arg0 : 32);}\n";
            source << "syscall:freebsd:" << name << ":return\n/" << selected << " && self->pm_seen && (errno != 0 || (int64_t)arg0 <= 0)/\n{";
            Head(source,5); Trace(source,"1"); source << "}\n";
        }
    }
    source << "syscall:freebsd::return\n/" << predicate << " && self->pm_seen/\n{";
    Head(source,2); Trace(source,"timestamp - self->pm_start"); Trace(source,"arg0"); Trace(source,"errno");
    source << "self->pm_seen = 0; self->pm_start = 0; self->pm_count = 0;\n";
    for (unsigned i = 0; i < 8; ++i) source << "self->pm_a" << i << " = 0;\n";
    source << "}\n";
    source << "dtrace:::END {"; Trace(source,std::to_string(Protocol)); Trace(source,"9"); Trace(source,"timestamp"); source << "}\n";
    return source.str();
}
ApplicationCapture::ApplicationCapture(CaptureOptions options, std::optional<std::uint64_t> origin): options(std::move(options)), origin(origin)
{ for (const auto& schema : this->options.schemas) schemas.emplace(schema.syscallName, schema); }
ApplicationCapture::~ApplicationCapture() = default;
void ApplicationCapture::Start()
{
    SessionOptions transport; transport.bufferSize = "16m"; transport.dynamicVariableSize = "16m";
    transport.maximumBatchBytes = 64 * 1024 * 1024; transport.maximumBatchRecords = 1000000; transport.maximumBatchProbes = 65536;
    if (!session.Start(ApplicationProgram(options, getpid()), {}, transport)) throw std::runtime_error(session.Status().diagnostic);
}
void ApplicationCapture::Stop(bool requestedCancellation)
{ cancellation |= requestedCancellation; if (!stopping) { stopping = true; if (!session.Stop()) throw std::runtime_error(session.Status().diagnostic); } }
void ApplicationCapture::Consume(const CapturedProbe& probe)
{
    std::vector<std::uint64_t> values; std::optional<std::string> text; std::vector<std::uint8_t> memory; std::vector<std::uint64_t> stack;
    for (const auto& record : probe.records)
    {
        if (record.bytes.empty()) continue;
        if (record.action == DTRACEACT_DIFEXPR && record.bytes.size() == 8)
        { std::uint64_t value; std::memcpy(&value, record.bytes.data(), 8); values.push_back(value); }
        else if (record.action == DTRACEACT_DIFEXPR && record.bytes.size() == 257)
        { const auto* end = static_cast<const std::uint8_t*>(std::memchr(record.bytes.data(),0,257));
          if (!end || text) throw std::runtime_error("invalid application string record");
          text = std::string(reinterpret_cast<const char*>(record.bytes.data()),end - record.bytes.data()); }
        else if (record.action == DTRACEACT_USTACK && record.bytes.size() == 17 * 8 &&
            DTRACE_USTACK_NFRAMES(record.argument) == 16 && DTRACE_USTACK_STRSIZE(record.argument) == 0)
        { stack.resize(17); std::memcpy(stack.data(),record.bytes.data(),17 * 8); }
        else if (record.action == DTRACEACT_TRACEMEM && record.bytes.size() == 32) memory = record.bytes;
        else if (record.action == DTRACEACT_TRACEMEM_DYNSIZE && record.bytes.size() == 8) { /* Native tracemem length record. */ }
        else throw std::runtime_error("unsupported application record action/width: " + std::to_string(record.action) + "/" + std::to_string(record.bytes.size()));
    }
    if (values.size() < 3 || values[0] != Protocol) throw std::runtime_error("invalid application protocol header");
    const auto kind = values[1];
    if (probe.provider == "dtrace")
    {
        if (values.size() != 3 || !probe.function.empty() || !probe.module.empty()) throw std::runtime_error("invalid application boundary");
        if (kind == 0 && probe.name == "BEGIN" && !quality.start)
        { quality.start = values[2]; if (!origin) origin = values[2]; }
        else if (kind == 9 && probe.name == "END" && !quality.end) quality.end = values[2];
        else throw std::runtime_error("duplicate or unsupported application boundary");
        return;
    }
    auto schema = schemas.find(probe.function);
    if (probe.provider != "syscall" || probe.module != "freebsd" || schema == schemas.end() || values.size() < 5 ||
        !values[2] || values[2] > INT32_MAX || !values[3] || values[3] > INT32_MAX)
        throw std::runtime_error("invalid application probe scope/identity");
    if (!options.targets.empty() && std::none_of(options.targets.begin(), options.targets.end(), [&](const auto& target) { return target.pid == values[2]; }))
        throw std::runtime_error("application observed an unselected PID");
    Key key{values[2], values[3], probe.function, values[4]};
    auto found = pending.find(key);
    if (found == pending.end())
    {
        if (pending.size() >= 65536) throw std::runtime_error("application correlation limit reached");
        Pending item; item.event.data.pid = values[2]; item.event.data.tid = values[3]; item.event.data.rawStart = values[4]; item.event.data.syscall = probe.function;
        found = pending.emplace(std::move(key),std::move(item)).first;
    }
    auto& item = found->second; auto& event = item.event.data;
    if (kind == 1)
    {
        auto count = schema->second.argumentTypes.size();
        if (item.entry || probe.name != "entry" || values.size() != 19 || values[7] != count || !text ||
            values[5] > UINT32_MAX || values[6] > UINT32_MAX) throw std::runtime_error("invalid application entry");
        item.entry = event.entryPresent = true; event.uid = values[5]; event.gid = values[6]; event.command = *text;
        item.event.birthSeconds = values[8]; item.event.birthMicroseconds = values[9]; item.event.imageAddress = values[10];
        for (unsigned index = 0; index < count; ++index)
            event.arguments.push_back({ArgumentName(event.syscall,index),schema->second.argumentTypes[index],values[11 + index],std::nullopt,false});
        if (!stack.empty())
        { if (stack[0] != event.pid) throw std::runtime_error("application stack PID mismatch");
          for (std::size_t index = 1; index < stack.size(); ++index) if (stack[index]) event.stack.push_back(stack[index]); }
        if (NoReturn(event.syscall)) event.state = EventState::EntryOnly;
    }
    else if (kind == 2)
    {
        if (item.returned || probe.name != "return" || values.size() != 8) throw std::runtime_error("invalid application return");
        item.returned = event.returnPresent = true; item.rawDuration = values[5]; item.rawResult = values[6]; item.rawErrno = values[7];
    }
    else if (kind == 3 || kind == 4)
    {
        // A fault in an optional copy action may leave only its scalar prefix.
        // Keep the independent entry/return evidence; final quality records the
        // unavailable snapshot and native runtime error rather than invent data.
        if (quality.runtimeErrors && ((kind == 3 && values.size() == 6 && !text) ||
            (kind == 4 && values.size() == 7 && memory.empty()))) return;
        if (values.size() != (kind == 3 ? 6U : 7U) || values[5] >= schema->second.argumentTypes.size() ||
            (kind == 3 && !text) || (kind == 4 && (values[6] > 32 || memory.size() != 32)))
            throw std::runtime_error("invalid application argument snapshot");
        if (!item.extras.emplace(static_cast<unsigned>(values[5]), kind == 3 ? *text :
            std::string(reinterpret_cast<const char*>(memory.data()),values[6])).second)
            throw std::runtime_error("duplicate application argument snapshot");
    }
    else if (kind == 5)
    {
        if (values.size() != 6 || values[5] >= schema->second.argumentTypes.size() ||
            !item.extras.emplace(static_cast<unsigned>(values[5]),std::string{}).second)
            throw std::runtime_error("invalid empty application buffer snapshot");
    }
    else throw std::runtime_error("unsupported application record kind");
}
void ApplicationCapture::Flush(std::vector<CapturedEvent>& output, bool final)
{
    if (!origin || !quality.start) { if (final) throw std::runtime_error("application capture missing BEGIN"); return; }
    for (auto it = pending.begin(); it != pending.end();)
    {
        auto& item = it->second; auto& event = item.event.data;
        const bool noReturn = NoReturn(event.syscall);
        const auto expected = ExtraCount(schemas.at(event.syscall),options,item.entry,item.returned);
        if (!final && (!item.entry || (!item.returned && !noReturn) || item.extras.size() < expected)) { ++it; continue; }
        if (item.entry)
        {
            if (event.rawStart < *origin) throw std::runtime_error("application clock precedes capture origin");
            event.timestamp = event.rawStart - *origin; maximumObservedTime = std::max(maximumObservedTime,event.rawStart);
            for (const auto& extra : item.extras)
            { event.arguments.at(extra.first).text = extra.second; event.arguments.at(extra.first).atLimit = extra.second.size() >= (Paths(event.syscall).empty() ? 32U : 256U); }
        }
        if (item.entry && item.returned)
        {
            if (item.rawDuration > UINT64_MAX - event.rawStart) throw std::runtime_error("application duration overflow");
            maximumObservedTime = std::max(maximumObservedTime,event.rawStart + item.rawDuration);
            event.duration = item.rawDuration; event.errnoBits = item.rawErrno;
            if (item.rawErrno <= INT32_MAX) { event.result = Signed(item.rawResult); event.state = EventState::Completed; }
            else if (item.rawErrno == UINT64_MAX) event.state = EventState::Restarted;
            else if (item.rawErrno == UINT64_MAX - 1) event.state = EventState::ControlTransfer;
            else { event.state = EventState::Incomplete; ++quality.unresolved; }
        }
        else if (!noReturn || !item.entry)
        { event.state = item.entry && cancellation ? EventState::Cancelled : EventState::Incomplete;
          if (event.state == EventState::Incomplete) ++quality.unresolved; }
        if (item.extras.size() < expected) quality.missingExtras += expected - item.extras.size();
        output.push_back(std::move(item.event)); it = pending.erase(it);
    }
    if (final && (!quality.end || *quality.end < *quality.start || maximumObservedTime > *quality.end))
        throw std::runtime_error("application missing or inconsistent END boundary");
}
std::vector<CapturedEvent> ApplicationCapture::Poll()
{
    if (quality.done) return {};
    auto batch = session.Poll();
    if (batch.outcome == PollOutcome::Error) throw std::runtime_error(session.Status().diagnostic);
    for (const auto& notice : batch.notices)
    { if (notice.kind == NoticeKind::Drop) quality.drops += notice.count; else quality.runtimeErrors += notice.count; }
    for (const auto& probe : batch.probes) Consume(probe);
    const bool final = batch.outcome == PollOutcome::Done;
    if (final && !stopping) throw std::runtime_error("application capture ended unexpectedly");
    std::vector<CapturedEvent> output; Flush(output,final);
    if (final)
    { session.Close(); quality.closed = session.Status().closed; quality.done = true;
      if (session.Status().failed || !session.Status().drained || session.Status().discarded) throw std::runtime_error("application transport did not drain cleanly"); }
    return output;
}
} // namespace procmon::freebsd::app
