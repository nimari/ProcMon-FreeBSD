// SPDX-License-Identifier: MIT
#pragma once
#include "storage.h"
#include <ostream>
namespace procmon::freebsd::app
{
void Dump(NativeStorage& storage, const std::vector<pid_t>& pids, const std::vector<Event>& events, std::ostream& out);
}
