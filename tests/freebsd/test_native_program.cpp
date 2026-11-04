// SPDX-License-Identifier: MIT
#include "../../src/tracer/freebsd/native_program.h"

#include <iostream>
#include <locale>
#include <stdexcept>

using namespace procmon::freebsd;
static unsigned int checks;
static void Check(bool value)
{
    ++checks;
    if (!value) throw std::runtime_error("generator check " + std::to_string(checks) + " failed");
}
static void Invalid(const NativeProgramRequest& request)
{
    bool rejected = false;
    try { (void)BuildNativeProgram(request); }
    catch (const std::invalid_argument&) { rejected = true; }
    Check(rejected);
}
struct GroupedNumbers : std::numpunct<char>
{
    char do_thousands_sep() const override { return ','; }
    std::string do_grouping() const override { return "\3"; }
};
int main()
{
    try
    {
        Invalid({0, 99, {NativeOperation::Read}});
        Invalid({42, 0, {NativeOperation::Read}});
        Invalid({std::uint64_t(INT32_MAX) + 1, 99, {NativeOperation::Read}});
        Invalid({42, UINT64_MAX, {NativeOperation::Read}});
        Invalid({42, 99, {}});
        Invalid({42, 99, {static_cast<NativeOperation>(99)}});
        auto a = BuildNativeProgram({42, 99, {NativeOperation::Write, NativeOperation::Read,
            NativeOperation::OpenAt, NativeOperation::Read}});
        auto b = BuildNativeProgram({42, 99, {NativeOperation::OpenAt, NativeOperation::Read, NativeOperation::Write}});
        Check(a.schemaVersion == 1 && a.targetPid == 42 && a.excludedPid == 99);
        Check(a.operations == b.operations && a.operations.size() == 3 && a.source == b.source);
        Check(a.source.find("getpgid") == std::string::npos && a.source.find("active") == std::string::npos);
        for (unsigned int mask = 1; mask < 8; ++mask)
        {
            NativeProgramRequest request{42, 99, {}};
            unsigned int count = 0;
            for (unsigned int bit = 0; bit < 3; ++bit)
                if (mask & (1U << bit)) { request.operations.push_back(static_cast<NativeOperation>(bit)); ++count; }
            auto program = BuildNativeProgram(request);
            Check(program.operations.size() == count && !program.source.empty());
        }
        auto self = BuildNativeProgram({42, 42, {NativeOperation::Read}});
        Check(self.targetPid == self.excludedPid && self.operations.size() == 1);
        auto maximum = BuildNativeProgram({INT32_MAX, INT32_MAX - 1, {NativeOperation::Read}});
        Check(maximum.targetPid == INT32_MAX);
        auto plain = BuildNativeProgram({12345, 54321, {NativeOperation::Read}});
        auto original = std::locale();
        std::locale::global(std::locale(original, new GroupedNumbers));
        auto grouped = BuildNativeProgram({12345, 54321, {NativeOperation::Read}});
        std::locale::global(original);
        Check(plain.source == grouped.source);
        std::cout << "PASS: " << checks << " native program validation/canonicalization checks\n";
        return 0;
    }
    catch (const std::exception& error) { std::cerr << "FAIL: " << error.what() << '\n'; return 1; }
}
