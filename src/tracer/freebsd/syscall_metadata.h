// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace procmon::freebsd
{

enum class ProbeKind { Entry, Return };
enum class MetadataState { Complete, Partial, Unavailable };

struct MetadataAttributes
{
    std::string nameStability;
    std::string dataStability;
    std::string dependencyClass;
};

struct ArgumentMetadata
{
    // Absent on resolution failure; diagnostic explains why.
    std::optional<std::string> typeName;
    // DTT_FL_USER metadata, not permission to dereference a pointer.
    bool userType = false;
    std::string diagnostic;
};

struct ProbeMetadata
{
    std::string function;
    ProbeKind kind = ProbeKind::Entry;
    std::optional<MetadataAttributes> attributes;
    std::optional<MetadataAttributes> argumentAttributes;
    // Absent when the query/count is unusable. Present zero is distinct.
    std::optional<std::size_t> argumentCount;
    std::vector<ArgumentMetadata> arguments;
    std::string diagnostic;
};

struct MetadataSnapshot
{
    // Consult the state first. Partial failures are recorded on the affected
    // probe/argument; discovery-wide failures appear in diagnostics below.
    MetadataState state = MetadataState::Unavailable;
    std::vector<ProbeMetadata> probes;
    std::vector<std::string> diagnostics;
};

// Discover advertised syscall:freebsd metadata for native amd64. All values are
// owned and remain usable after the library handle closes. No probes are enabled
// and no modules are loaded. API failures are returned as diagnostics; C++
// allocation failures propagate after cleanup. Calls are synchronous; callers
// must serialize use rather than assume libdtrace is thread-safe.
//
// Complete means all discovered positional metadata resolved and both probe
// kinds paired. It does not establish callable/semantic syscall coverage: names
// can include obsolete, compatibility, reserved, and optional-module entries.
// Argument names, direction, syscall numbers, values and decoding rules are not
// supplied here. This is an internal component, not a persisted trace format.
MetadataSnapshot DiscoverNativeSyscallMetadata();

} // namespace procmon::freebsd
