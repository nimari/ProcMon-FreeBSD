// SPDX-License-Identifier: MIT
#include "storage.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>

namespace procmon::freebsd::app
{
namespace
{
constexpr int ApplicationId = 0x504d4642;
struct Connection
{
    sqlite3* db = nullptr;
    ~Connection() { if (db) sqlite3_close(db); }
};
void Check(int result, sqlite3* db)
{ if (result != SQLITE_OK) throw std::runtime_error(std::string("FreeBSD SQLite: ") + sqlite3_errmsg(db)); }
void Execute(sqlite3* db, const std::string& sql)
{ Check(sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr), db); }
struct Statement
{
    sqlite3* db; sqlite3_stmt* statement = nullptr;
    Statement(sqlite3* db, const std::string& sql): db(db) { Check(sqlite3_prepare_v2(db, sql.c_str(), -1, &statement, nullptr), db); }
    ~Statement() { sqlite3_finalize(statement); }
    void Text(int index, const std::string& value)
    { Check(sqlite3_bind_text(statement, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT), db); }
    void Integer(int index, std::int64_t value) { Check(sqlite3_bind_int64(statement, index, value), db); }
    bool Row() { auto result = sqlite3_step(statement); if (result == SQLITE_ROW) return true;
        if (result != SQLITE_DONE) Check(result, db); return false; }
};
std::string Text(sqlite3_stmt* statement, int index)
{
    const auto* data = sqlite3_column_text(statement, index); int size = sqlite3_column_bytes(statement, index);
    if (!data) return {}; return {reinterpret_cast<const char*>(data), static_cast<std::size_t>(size)};
}
std::int64_t Integer(sqlite3* db, const std::string& sql)
{ Statement query(db, sql); if (!query.Row()) throw std::runtime_error("missing FreeBSD database metadata"); return sqlite3_column_int64(query.statement, 0); }
std::string Sort(ScreenConfiguration::sort sort)
{
    switch (sort) { case ScreenConfiguration::pid: return "pid"; case ScreenConfiguration::process: return "process";
        case ScreenConfiguration::operation: return "syscall"; case ScreenConfiguration::result: return "result";
        case ScreenConfiguration::duration: return "duration"; default: return "timestamp"; }
}
void Backup(sqlite3* destination, sqlite3* source)
{
    sqlite3_backup* backup = sqlite3_backup_init(destination, "main", source, "main");
    if (!backup) throw std::runtime_error(std::string("cannot start FreeBSD database backup: ") + sqlite3_errmsg(destination));
    int result = sqlite3_backup_step(backup, -1);
    int finished = sqlite3_backup_finish(backup);
    if (result != SQLITE_DONE) Check(result, destination); Check(finished, destination);
}
void Metadata(sqlite3* db, const std::string& key, const std::string& value)
{
    Statement statement(db, "INSERT OR REPLACE INTO capture(key,value) VALUES(?,?)");
    statement.Text(1, key); statement.Text(2, value); (void)statement.Row();
}
void Validate(sqlite3* db)
{
    if (Integer(db, "PRAGMA application_id") != ApplicationId || Integer(db, "PRAGMA user_version") != 1)
        throw std::runtime_error("not a supported ProcMon FreeBSD trace (Linux/legacy files are not reinterpreted)");
    Statement integrity(db, "PRAGMA quick_check");
    if (!integrity.Row() || Text(integrity.statement, 0) != "ok") throw std::runtime_error("corrupt FreeBSD trace");
    if (Integer(db, "SELECT count(*) FROM events") > 1000000) throw std::runtime_error("FreeBSD trace exceeds event limit");
    if (Integer(db, "SELECT count(*) FROM capture") > 256 ||
        Integer(db, "SELECT count(*) FROM capture WHERE typeof(key)!='text' OR typeof(value)!='text' OR length(key)>256 OR length(value)>4096") ||
        Integer(db, "SELECT count(*) FROM sqlite_schema WHERE type IN ('view','trigger') OR (type='table' AND name NOT IN ('events','capture'))"))
        throw std::runtime_error("invalid FreeBSD trace schema/metadata");
    Statement platform(db,"SELECT value FROM capture WHERE key='platform'");
    if (!platform.Row() || Text(platform.statement,0) != "FreeBSD-amd64") throw std::runtime_error("unsupported FreeBSD trace platform");
    if (Integer(db,"SELECT coalesce(sum(length(data)+length(details)+length(process)+length(syscall)),0) FROM events") > 256 * 1024 * 1024)
        throw std::runtime_error("input trace exceeds replay payload budget (256 MiB)");
    Statement rows(db, "SELECT id,pid,process,syscall,result,timestamp,duration,data,details FROM events");
    while (rows.Row())
    {
        auto* row = rows.statement;
        const auto data = Telemetry(Decode(sqlite3_column_blob(row,7),sqlite3_column_bytes(row,7)));
        if (sqlite3_column_type(row,0) != SQLITE_INTEGER || sqlite3_column_int64(row,0) <= 0 ||
            sqlite3_column_type(row,1) != SQLITE_INTEGER || sqlite3_column_int64(row,1) != data.pid ||
            sqlite3_column_type(row,2) != SQLITE_TEXT || Text(row,2) != data.processName ||
            sqlite3_column_type(row,3) != SQLITE_TEXT || Text(row,3) != data.syscall ||
            (data.native->result ? sqlite3_column_type(row,4) != SQLITE_INTEGER || sqlite3_column_int64(row,4) != *data.native->result : sqlite3_column_type(row,4) != SQLITE_NULL) ||
            sqlite3_column_type(row,5) != SQLITE_INTEGER || sqlite3_column_int64(row,5) != static_cast<std::int64_t>(data.timestamp) ||
            (data.native->duration ? sqlite3_column_type(row,6) != SQLITE_INTEGER || sqlite3_column_int64(row,6) != *data.native->duration : sqlite3_column_type(row,6) != SQLITE_NULL) ||
            sqlite3_column_type(row,7) != SQLITE_BLOB || sqlite3_column_type(row,8) != SQLITE_TEXT || Text(row,8) != Details(*data.native))
            throw std::runtime_error("FreeBSD trace index columns disagree with typed payload");
    }
}
}
ITelemetry Telemetry(const EventData& event)
{
    if (!event.pid || event.pid > INT32_MAX || !event.tid || event.tid > INT32_MAX || event.uid > UINT32_MAX || event.gid > UINT32_MAX || event.syscall.empty() ||
        (event.timestamp && *event.timestamp >= INT64_MAX) || (event.duration && *event.duration > INT64_MAX))
        throw std::runtime_error("FreeBSD event identity/time is outside native storage bounds");
    ITelemetry data{};
    data.pid = static_cast<pid_t>(event.pid); data.comm = event.command; data.processName = Escape(event.command);
    data.syscall = event.syscall; data.result = event.result.value_or(0); data.timestamp = event.timestamp ? *event.timestamp + 1 : 0;
    data.duration = event.duration.value_or(0); data.stackTrace.userIPs = event.stack; data.stackTrace.userSymbols = event.symbols;
    data.native = std::make_shared<EventData>(event); return data;
}
NativeStorage::~NativeStorage() { if (database) sqlite3_close(database); }
bool NativeStorage::Initialize(const std::vector<Event>&)
{
    std::lock_guard<std::mutex> lock(mutex);
    if (database) return false;
    Check(sqlite3_open_v2(":memory:", &database, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr), database);
    Execute(database, "PRAGMA application_id=1347241538; PRAGMA user_version=1;"
        "CREATE TABLE capture(key TEXT PRIMARY KEY,value TEXT NOT NULL);"
        "CREATE TABLE events(id INTEGER PRIMARY KEY,pid INTEGER NOT NULL,process TEXT NOT NULL,syscall TEXT NOT NULL,"
        "result INTEGER,timestamp INTEGER NOT NULL,duration INTEGER,data BLOB NOT NULL,details TEXT NOT NULL);"
        "CREATE INDEX events_pid_time ON events(pid,timestamp); CREATE INDEX events_syscall ON events(syscall);");
    app::Metadata(database, "platform", "FreeBSD-amd64"); app::Metadata(database, "clock", "DTrace session nanoseconds");
    app::Metadata(database, "status", "capturing"); app::Metadata(database,"complete","false"); return true;
}
void NativeStorage::Insert(const ITelemetry& data)
{
    if (!data.native) throw std::runtime_error("missing typed FreeBSD event");
    const auto checked = Telemetry(*data.native); const auto bytes = Encode(*data.native);
    const auto details = Details(*data.native);
    const auto cost = bytes.size() + details.size() + checked.processName.size() + checked.syscall.size();
    if (storedEvents >= maximumEvents || cost > maximumBytes - std::min(storedBytes,maximumBytes))
        throw std::runtime_error("capture storage budget reached; narrow PID/events or increase --max-events/--max-bytes");
    Statement statement(database, "INSERT INTO events(pid,process,syscall,result,timestamp,duration,data,details) VALUES(?,?,?,?,?,?,?,?)");
    statement.Integer(1, checked.pid); statement.Text(2, checked.processName); statement.Text(3, checked.syscall);
    if (data.native->result) statement.Integer(4, *data.native->result);
    statement.Integer(5, checked.timestamp); if (data.native->duration) statement.Integer(6, *data.native->duration);
    Check(sqlite3_bind_blob(statement.statement, 7, bytes.data(), static_cast<int>(bytes.size()), SQLITE_TRANSIENT), database);
    statement.Text(8, details); (void)statement.Row(); ++storedEvents; storedBytes += cost;
}
bool NativeStorage::Store(ITelemetry data) { return StoreMany({std::move(data)}); }
bool NativeStorage::StoreMany(std::vector<ITelemetry> data)
{
    std::lock_guard<std::mutex> lock(mutex);
    if (!database) return false;
    const auto previousEvents = storedEvents, previousBytes = storedBytes;
    Execute(database, "BEGIN");
    try { for (const auto& event : data) Insert(event); Execute(database, "COMMIT"); }
    catch (...) { Execute(database, "ROLLBACK"); storedEvents = previousEvents; storedBytes = previousBytes; throw; }
    return true;
}
int NativeStorage::Size() { std::lock_guard<std::mutex> lock(mutex); return static_cast<int>(storedEvents); }
bool NativeStorage::Clear() { std::lock_guard<std::mutex> lock(mutex); Execute(database, "DELETE FROM events"); storedEvents = storedBytes = 0; return true; }
void NativeStorage::Limits(std::uint64_t events,std::uint64_t bytes)
{
    std::lock_guard<std::mutex> lock(mutex);
    if (!events || events > 1000000 || !bytes || bytes > 256 * 1024 * 1024 || storedEvents > events || storedBytes > bytes)
        throw std::invalid_argument("invalid capture storage budget");
    maximumEvents = events; maximumBytes = bytes;
    app::Metadata(database,"maximum_events",std::to_string(events)); app::Metadata(database,"maximum_payload_bytes",std::to_string(bytes));
}
void NativeStorage::Visit(const std::vector<pid_t>& pids,const std::vector<Event>& events,const std::function<void(const ITelemetry&)>& visitor)
{ (void)Select(pids,events,{},ScreenConfiguration::time,true,1000000,0,0,0,std::nullopt,visitor); }
void NativeStorage::Metadata(const std::string& key, const std::string& value)
{ std::lock_guard<std::mutex> lock(mutex); app::Metadata(database, key, value); }
std::map<std::string,std::string> NativeStorage::Metadata()
{
    std::lock_guard<std::mutex> lock(mutex); std::map<std::string,std::string> result;
    Statement query(database, "SELECT key,value FROM capture"); while (query.Row()) result.emplace(Text(query.statement, 0), Text(query.statement, 1)); return result;
}
std::vector<ITelemetry> NativeStorage::Select(std::vector<pid_t> pids, const std::vector<Event>& events, std::string filter,
    ScreenConfiguration::sort sort, bool asc, std::uint64_t limit, std::uint64_t offset, double start, double end, std::optional<int> result, const std::function<void(const ITelemetry&)>& visitor)
{
    std::lock_guard<std::mutex> lock(mutex);
    if (pids.size() > 10 || events.size() > 1024 || filter.size() > 4096 || !std::isfinite(start) || !std::isfinite(end) ||
        start < 0 || end < 0 || start >= static_cast<double>(INT64_MAX) || end >= static_cast<double>(INT64_MAX))
        throw std::runtime_error("invalid FreeBSD trace query bounds");
    std::string sql = "SELECT data FROM events WHERE 1";
    if (!pids.empty()) { sql += " AND pid IN (?"; for (std::size_t i = 1; i < pids.size(); ++i) sql += ",?"; sql += ')'; }
    if (!events.empty()) { sql += " AND syscall IN (?"; for (std::size_t i = 1; i < events.size(); ++i) sql += ",?"; sql += ')'; }
    if (!filter.empty()) sql += " AND (process LIKE ? OR syscall LIKE ? OR details LIKE ? OR CAST(pid AS TEXT) LIKE ? OR CAST(result AS TEXT) LIKE ?)";
    if (start) sql += " AND timestamp>=?"; if (end) sql += " AND timestamp<=?"; if (result) sql += " AND result=?";
    sql += " ORDER BY " + Sort(sort) + (asc ? " ASC,id ASC" : " DESC,id DESC") + " LIMIT ? OFFSET ?";
    Statement query(database, sql); int index = 1;
    for (auto pid : pids) query.Integer(index++, pid); for (const auto& event : events) query.Text(index++, event.Name());
    if (!filter.empty()) for (int i = 0; i < 5; ++i) query.Text(index++, "%" + filter + "%");
    if (start) query.Integer(index++, static_cast<std::int64_t>(start)); if (end) query.Integer(index++, static_cast<std::int64_t>(end));
    if (result) query.Integer(index++, *result); query.Integer(index++, std::min<std::uint64_t>(limit, 1000000));
    query.Integer(index, std::min<std::uint64_t>(offset, INT64_MAX));
    std::vector<ITelemetry> rows;
    while (query.Row())
    { auto data = Telemetry(Decode(sqlite3_column_blob(query.statement,0),sqlite3_column_bytes(query.statement,0)));
      if (visitor) visitor(data); else rows.push_back(std::move(data)); }
    return rows;
}
std::vector<ITelemetry> NativeStorage::QueryByPid(pid_t pid, const std::vector<Event>& events) { return QueryByPids({pid}, events); }
std::vector<ITelemetry> NativeStorage::QueryByPids(std::vector<pid_t> pids, const std::vector<Event>& events) { return Select(pids, events, {}, ScreenConfiguration::time, true, 1000000, 0); }
std::vector<ITelemetry> NativeStorage::QueryByPidInTimespan(pid_t pid, double start, double end, const std::vector<Event>& events) { return QueryByPidsInTimespan({pid}, start, end, events); }
std::vector<ITelemetry> NativeStorage::QueryByPidsInTimespan(std::vector<pid_t> pids, double start, double end, const std::vector<Event>& events) { return Select(pids, events, {}, ScreenConfiguration::time, true, 1000000, 0, start, end); }
std::vector<ITelemetry> NativeStorage::QueryByResultCodeInTimespan(int result, double start, double end, const std::vector<Event>& events) { return Select({}, events, {}, ScreenConfiguration::time, true, 1000000, 0, start, end, result); }
std::vector<ITelemetry> NativeStorage::QueryByEventsinPage(std::vector<pid_t> pids, uint page, uint count, ScreenConfiguration::sort sort, bool asc, const std::vector<Event>& events) { return QueryByFilteredEventsinPage({}, pids, page, count, sort, asc, events); }
std::vector<ITelemetry> NativeStorage::QueryByFilteredEventsinPage(std::string filter, std::vector<pid_t> pids, uint page, uint count, ScreenConfiguration::sort sort, bool asc, const std::vector<Event>& events) { return Select(pids, events, filter, sort, asc, std::min(count, 10000U), static_cast<std::uint64_t>(page) * count); }
std::vector<int> NativeStorage::QueryIdsBySearch(std::string search, std::vector<pid_t> pids, ScreenConfiguration::sort sort, bool asc, const std::vector<Event>& events)
{
    std::vector<int> result; std::size_t index = 0;
    std::transform(search.begin(), search.end(), search.begin(), [](unsigned char c) { return std::tolower(c); });
    (void)Select(pids,events,{},sort,asc,1000000,0,0,0,std::nullopt,[&](const ITelemetry& row)
    { ++index; auto text = row.processName + " " + row.syscall + " " + Details(*row.native) + " " + std::to_string(row.result);
      std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return std::tolower(c); });
      if (text.find(search) != text.npos) result.push_back(static_cast<int>(index)); });
    return result;
}
std::map<std::string,std::tuple<int,std::uint64_t>> NativeStorage::GetHitmap()
{
    std::lock_guard<std::mutex> lock(mutex); std::map<std::string,std::tuple<int,std::uint64_t>> result;
    Statement query(database, "SELECT syscall,duration FROM events");
    while (query.Row())
    {
        auto& item = result[Text(query.statement, 0)];
        const auto duration = static_cast<std::uint64_t>(sqlite3_column_int64(query.statement, 1));
        if (duration > UINT64_MAX - std::get<1>(item)) throw std::runtime_error("FreeBSD duration aggregate overflow");
        ++std::get<0>(item); std::get<1>(item) += duration;
    }
    return result;
}
bool NativeStorage::Export(std::tuple<std::uint64_t,std::string> start, std::string path)
{
    std::lock_guard<std::mutex> lock(mutex);
    if (path.empty()) throw std::runtime_error("empty output trace path");
    app::Metadata(database, "start_time", std::to_string(std::get<0>(start))); app::Metadata(database, "epoch", std::get<1>(start));
    std::string temporary = path + ".tmp.XXXXXX"; std::vector<char> name(temporary.begin(), temporary.end()); name.push_back(0);
    int fd = mkstemp(name.data()); if (fd < 0) throw std::runtime_error("cannot create private trace output temporary file"); close(fd);
    try
    {
        { Connection destination; Check(sqlite3_open_v2(name.data(), &destination.db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW, nullptr), destination.db); Backup(destination.db, database); }
        if (link(name.data(), path.c_str()) != 0) throw std::runtime_error("cannot publish trace (output already exists or destination is not writable)");
        unlink(name.data()); return true;
    }
    catch (...) { unlink(name.data()); throw; }
}
std::tuple<std::uint64_t,std::string> NativeStorage::Load(std::string path)
{
    std::lock_guard<std::mutex> lock(mutex);
    struct stat info{}; if (stat(path.c_str(), &info) || !S_ISREG(info.st_mode) || info.st_size > 2147483648LL)
        throw std::runtime_error("invalid or oversized input trace file");
    Connection source; Check(sqlite3_open_v2(path.c_str(), &source.db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW | SQLITE_OPEN_PRIVATECACHE, nullptr), source.db);
    // The SQLite row includes escaped query columns in addition to the bounded
    // 128 KiB typed blob. Keep a separate, larger row limit.
    sqlite3_limit(source.db, SQLITE_LIMIT_LENGTH, 1048576); sqlite3_limit(source.db, SQLITE_LIMIT_COLUMN, 64);
    Execute(source.db, "PRAGMA trusted_schema=OFF"); Validate(source.db);
    Backup(database, source.db);
    storedEvents = Integer(database,"SELECT count(*) FROM events");
    storedBytes = Integer(database,"SELECT coalesce(sum(length(data)+length(details)+length(process)+length(syscall)),0) FROM events");
    Statement query(database, "SELECT value FROM capture WHERE key=?"); query.Text(1, "epoch");
    const auto epoch = query.Row() ? Text(query.statement, 0) : "unknown";
    return {1, epoch}; // Stored native timestamps are already session-relative + 1.
}
} // namespace procmon::freebsd::app
