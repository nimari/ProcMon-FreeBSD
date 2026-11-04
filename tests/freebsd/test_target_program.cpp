// SPDX-License-Identifier: MIT
#include "../../src/tracer/freebsd/native_program.h"
#include <iostream>
#include <stdexcept>
using namespace procmon::freebsd;
int main()
{
    unsigned checks = 0;
    auto check = [&](bool value) { ++checks; if (!value) throw std::runtime_error("guard generation check failed"); };
    NativeProgramRequest request{42, 99, {NativeOperation::OpenAt, NativeOperation::Read, NativeOperation::Write}};
    const auto plain = BuildNativeProgram(request).source;
    request.identity = NativeTargetIdentity{18446744073709550000ULL, 123, 456789};
    const auto guarded = BuildNativeProgram(request).source;
    for (const auto* clause : {"(uint64_t)curthread->td_proc == 18446744073709550000ULL", "p_start.tv_sec == 123LL",
        "p_start.tv_usec == 456789", "stringof(curthread->td_proc->p_sysent->sv_name) == \"FreeBSD ELF64\""})
    {
        std::size_t count = 0, position = 0;
        while ((position = guarded.find(clause, position)) != guarded.npos) { ++count; ++position; }
        check(count == 6 && plain.find(clause) == plain.npos);
    }
    for (const auto identity : {NativeTargetIdentity{0, 1, 1}, {1, UINT64_MAX, 1}, {1, 1, 1000000}})
    {
        request.identity = identity; bool rejected = false;
        try { (void)BuildNativeProgram(request); } catch (const std::invalid_argument&) { rejected = true; }
        check(rejected);
    }
    request.identity.reset(); check(BuildNativeProgram(request).source == plain);
    std::cout << "PASS: " << checks << " identity generation checks\n";
}
