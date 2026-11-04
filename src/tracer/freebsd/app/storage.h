// SPDX-License-Identifier: MIT
#pragma once
#include <mutex>
#include <functional>
#include <sqlite3.h>
#include "../../../storage/storage_engine.h"

namespace procmon::freebsd::app
{
ITelemetry Telemetry(const EventData& event);
class NativeStorage final : public IStorageEngine
{
public:
    ~NativeStorage() override;
    bool Initialize(const std::vector<Event>& events) override;
    bool Store(ITelemetry event) override;
    bool StoreMany(std::vector<ITelemetry> events) override;
    int Size() override;
    bool Clear() override;
    bool Export(std::tuple<std::uint64_t, std::string> start, std::string path) override;
    std::tuple<std::uint64_t, std::string> Load(std::string path) override;
    std::vector<ITelemetry> QueryByPid(pid_t pid, const std::vector<Event>& events = {}) override;
    std::vector<ITelemetry> QueryByPids(std::vector<pid_t> pids, const std::vector<Event>& events = {}) override;
    std::vector<ITelemetry> QueryByPidInTimespan(pid_t pid, double start = 0, double end = 0, const std::vector<Event>& events = {}) override;
    std::vector<ITelemetry> QueryByPidsInTimespan(std::vector<pid_t> pids, double start = 0, double end = 0, const std::vector<Event>& events = {}) override;
    std::vector<ITelemetry> QueryByResultCodeInTimespan(int result, double start = 0, double end = 0, const std::vector<Event>& events = {}) override;
    std::vector<ITelemetry> QueryByEventsinPage(std::vector<pid_t> pids, uint page, uint count, ScreenConfiguration::sort sort, bool asc, const std::vector<Event>& events = {}) override;
    std::vector<ITelemetry> QueryByFilteredEventsinPage(std::string filter, std::vector<pid_t> pids, uint page, uint count, ScreenConfiguration::sort sort, bool asc, const std::vector<Event>& events = {}) override;
    std::vector<int> QueryIdsBySearch(std::string search, std::vector<pid_t> pids, ScreenConfiguration::sort sort, bool asc, const std::vector<Event>& events = {}) override;
    std::map<std::string, std::tuple<int, std::uint64_t>> GetHitmap() override;
    void Limits(std::uint64_t events, std::uint64_t bytes);
    void Visit(const std::vector<pid_t>& pids, const std::vector<Event>& events, const std::function<void(const ITelemetry&)>& visitor);
    void Metadata(const std::string& key, const std::string& value);
    std::map<std::string, std::string> Metadata();
private:
    sqlite3* database = nullptr;
    std::mutex mutex;
    std::uint64_t maximumEvents = 100000, maximumBytes = 64 * 1024 * 1024;
    std::uint64_t storedEvents = 0, storedBytes = 0;
    void Insert(const ITelemetry& event);
    std::vector<ITelemetry> Select(std::vector<pid_t> pids, const std::vector<Event>& events, std::string filter,
        ScreenConfiguration::sort sort, bool asc, std::uint64_t limit, std::uint64_t offset,
        double start = 0, double end = 0, std::optional<int> result = std::nullopt,
        const std::function<void(const ITelemetry&)>& visitor = {});
};
}
