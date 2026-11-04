// SPDX-License-Identifier: MIT
#include "native_program.h"

#include <algorithm>
#include <locale>
#include <sstream>
#include <stdexcept>

namespace procmon::freebsd
{
namespace
{
const char* Name(NativeOperation operation)
{
    switch (operation)
    {
        case NativeOperation::OpenAt: return "openat";
        case NativeOperation::Read: return "read";
        case NativeOperation::Write: return "write";
    }
    throw std::invalid_argument("unsupported native syscall operation");
}

void Boundary(std::ostringstream& source, const char* name, std::uint64_t pid)
{
    source << "dtrace:::" << name << "\n{\n"
           << "    trace((uint64_t)" << pid << ");\n"
           << "    trace((uint64_t)timestamp);\n}\n\n";
}
} // namespace

NativeProgram BuildNativeProgram(const NativeProgramRequest& request)
{
    if (!request.targetPid || request.targetPid > INT32_MAX ||
        !request.monitorPid || request.monitorPid > INT32_MAX || request.operations.empty())
        throw std::invalid_argument("positive native PIDs and a nonempty syscall filter are required");
    if (request.identity && (!request.identity->processAddress ||
        request.identity->startSeconds > INT64_MAX || request.identity->startMicroseconds >= 1000000))
        throw std::invalid_argument("invalid native process identity");
    NativeProgram result;
    result.targetPid = request.targetPid;
    result.excludedPid = request.monitorPid;
    result.operations = request.operations;
    for (auto operation : result.operations) (void)Name(operation);
    std::sort(result.operations.begin(), result.operations.end());
    result.operations.erase(std::unique(result.operations.begin(), result.operations.end()), result.operations.end());
    std::ostringstream source;
    source.imbue(std::locale::classic());
    source << "/* Generated native schema v1; trusted numeric PIDs and fixed syscall names. */\n"
           << "#pragma D option strsize=65\n\n";
    Boundary(source, "BEGIN", request.targetPid);
    std::string predicate = "pid == " + std::to_string(request.targetPid) +
        " && pid != " + std::to_string(request.monitorPid);
    if (request.identity)
    {
        const auto& identity = *request.identity;
        predicate += " && (uint64_t)curthread->td_proc == " + std::to_string(identity.processAddress) +
            "ULL && curthread->td_proc->p_stats->p_start.tv_sec == " + std::to_string(identity.startSeconds) +
            "LL && curthread->td_proc->p_stats->p_start.tv_usec == " + std::to_string(identity.startMicroseconds) +
            " && stringof(curthread->td_proc->p_sysent->sv_name) == \"FreeBSD ELF64\"";
    }
    for (auto operation : result.operations)
    {
        const std::string name = Name(operation);
        const std::string state = "self->pm_" + name + "_";
        source << "syscall:freebsd:" << name << ":entry\n/" << predicate << "/\n{\n"
               << "    " << state << "seen = 0;\n"
               << "    " << state << "start = timestamp;\n"
               << "    " << state << "a0 = (int)arg0;\n"
               << "    " << state << "a2 = arg2;\n"
               << "    " << state << "path = " << (operation == NativeOperation::OpenAt ? "copyinstr(arg1, 64)" : "\"-\"") << ";\n"
               << "    " << state << "seen = 1;\n"
               << "    trace((uint64_t)pid);\n    trace((uint64_t)tid);\n"
               << "    trace((uint64_t)" << state << "start);\n"
               << "    trace((uint64_t)" << state << "a0);\n"
               << "    trace((uint64_t)" << state << "a2);\n"
               << "    trace(" << state << "path);\n}\n\n"
               << "syscall:freebsd:" << name << ":return\n/" << predicate << " && " << state << "seen/\n{\n"
               << "    trace((uint64_t)pid);\n    trace((uint64_t)tid);\n"
               << "    trace((uint64_t)" << state << "start);\n"
               << "    trace((uint64_t)(timestamp - " << state << "start));\n"
               << "    trace((uint64_t)arg0);\n    trace((uint64_t)errno);\n"
               << "    trace((uint64_t)" << state << "a0);\n"
               << "    trace((uint64_t)" << state << "a2);\n"
               << "    trace(" << state << "path);\n"
               << "    " << state << "seen = 0;\n"
               << "    " << state << "start = 0;\n"
               << "    " << state << "a0 = 0;\n"
               << "    " << state << "a2 = 0;\n"
               << "    " << state << "path = \"\";\n}\n\n";
    }
    Boundary(source, "END", request.targetPid);
    result.source = source.str();
    return result;
}

} // namespace procmon::freebsd
