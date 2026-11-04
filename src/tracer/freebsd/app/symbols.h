// SPDX-License-Identifier: MIT
#pragma once
#include "capture.h"
#include <map>
#include <memory>
namespace procmon::freebsd::app
{
// Captured symbol text is stored with the event, so replay never consults a new
// process with a recycled PID. Missing mappings/debug symbols remain explicit.
class NativeSymbols
{
public:
    NativeSymbols();
    ~NativeSymbols();
    void Prime(std::uint64_t pid);
    void Resolve(CapturedEvent& event);
private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};
}
