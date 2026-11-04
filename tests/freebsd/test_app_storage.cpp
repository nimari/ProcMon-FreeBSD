// SPDX-License-Identifier: MIT
#include "../../src/tracer/freebsd/app/storage.h"
#include <atomic>
#include <cstring>
#include <fstream>
#include <iostream>
#include <thread>
using namespace procmon::freebsd::app;
static unsigned checks;
static void Check(bool value) { ++checks; if (!value) throw std::runtime_error("application storage check " + std::to_string(checks)); }
template<class F> static void Reject(F function)
{ bool rejected = false; try { function(); } catch (const std::exception&) { rejected = true; } Check(rejected); }
static EventData Sample()
{
    EventData event;
    event.pid = 123; event.tid = 456; event.uid = 1001; event.gid = 0;
    event.rawStart = 18446744073709550000ULL; event.timestamp = 10; event.duration = 7;
    event.result = -2; event.errnoBits = 0; event.state = EventState::Completed;
    event.entryPresent = event.returnPresent = true; event.syscall = "mmap"; event.command = "test\033program";
    for (unsigned index = 0; index < 7; ++index)
        event.arguments.push_back({"arg" + std::to_string(index), "uint64_t", UINT64_MAX - index, std::nullopt, false});
    event.arguments[1].text = std::string("a\0\xff\"\\", 5); event.arguments[1].atLimit = true;
    event.stack = {0x1234, UINT64_MAX}; event.symbols = {"module!function", "[unavailable]"};
    return event;
}
int main(int argc, char** argv)
{
    try
    {
        Check(argc == 2); const std::string path = std::string(argv[1]) + "/app-storage.db";
        auto event = Sample(); const auto bytes = Encode(event);
        auto decoded = Decode(bytes.data(), bytes.size()); Check(Encode(decoded) == bytes);
        Check(decoded.arguments.size() == 7 && decoded.arguments[0].raw == UINT64_MAX && decoded.result == -2);
        Check(decoded.arguments[1].text == event.arguments[1].text && decoded.stack[1] == UINT64_MAX);
        Check(Details(decoded).find("\\x00\\xff") != std::string::npos);
        for (std::size_t count = 0; count < bytes.size(); ++count)
        { bool rejected = false; try { (void)Decode(bytes.data(), count); } catch (const std::runtime_error&) { rejected = true; } if (!rejected) throw std::runtime_error("accepted truncated event"); }
        Check(true);
        auto bad = bytes; bad[0] ^= 1; Reject([&] { Decode(bad.data(), bad.size()); });
        bad = bytes; bad[8] = 255; Reject([&] { Decode(bad.data(), bad.size()); });
        bad = bytes; bad.push_back(0); Reject([&] { Decode(bad.data(), bad.size()); });
        for (auto state : {EventState::EntryOnly, EventState::Restarted, EventState::ControlTransfer, EventState::Cancelled, EventState::Incomplete})
        { auto value = event; value.state = state; value.result.reset(); value.duration.reset(); value.errnoBits.reset();
          auto encoded = Encode(value); Check(Encode(Decode(encoded.data(), encoded.size())) == encoded); }
        auto many = event; many.arguments.resize(9); Reject([&] { Encode(many); });
        many = event; many.stack.resize(33); Reject([&] { Encode(many); });
        many = event; many.symbols.resize(3); Reject([&] { Encode(many); });
        many = event; many.command.assign(4097, 'x'); Reject([&] { Encode(many); });
        NativeStorage storage; Check(storage.Initialize({})); Check(!storage.Initialize({})); Check(storage.Metadata()["complete"] == "false");
        Check(storage.Store(Telemetry(event)) && storage.Size() == 1);
        auto second = event; second.pid = 999; second.tid = 1000; second.syscall = "read";
        second.result = -1; second.errnoBits = 4; second.timestamp = 30; second.duration = 9;
        Check(storage.Store(Telemetry(second)) && storage.Size() == 2);
        Check(storage.QueryByPid(123).size() == 1 && storage.QueryByPids({123,999}).size() == 2);
        Check(storage.QueryByPids({}, {Event("read")}).size() == 1);
        Check(storage.QueryByPidInTimespan(123, 0, 20).size() == 1 && storage.QueryByPidsInTimespan({}, 20, 40).size() == 1);
        Check(storage.QueryByResultCodeInTimespan(-1).size() == 1);
        Check(storage.QueryByEventsinPage({}, 0, 1, ScreenConfiguration::duration, false)[0].pid == 999);
        Check(storage.QueryByEventsinPage({}, 1, 1, ScreenConfiguration::duration, false)[0].pid == 123);
        Check(storage.QueryByFilteredEventsinPage("mmap", {}, 0, 10, ScreenConfiguration::time, true).size() == 1);
        Check(storage.QueryByFilteredEventsinPage("' OR 1=1 --", {}, 0, 10, ScreenConfiguration::time, true).empty());
        Check(storage.QueryIdsBySearch("READ", {}, ScreenConfiguration::time, true) == std::vector<int>{2});
        Check(std::get<0>(storage.GetHitmap()["mmap"]) == 1 && std::get<1>(storage.GetHitmap()["read"]) == 9);
        auto invalid = event; invalid.pid = 0;
        Reject([&] { storage.StoreMany({Telemetry(event), Telemetry(invalid)}); }); Check(storage.Size() == 2);
        ITelemetry invalidData{}; Reject([&] { storage.StoreMany({Telemetry(event), invalidData}); }); Check(storage.Size() == 2);
        storage.Metadata("status", "complete"); Check(storage.Export({1,"test epoch"}, path));
        Reject([&] { storage.Export({1,"overwrite"}, path); });
        NativeStorage loaded; loaded.Initialize({}); Check(std::get<1>(loaded.Load(path)) == "test epoch");
        const auto rows = loaded.QueryByPids({}); Check(rows.size() == 2 && Encode(*rows[0].native) == bytes);
        Check(loaded.Metadata()["status"] == "complete" && loaded.Metadata()["platform"] == "FreeBSD-amd64");
        const auto invalidPath = std::string(argv[1]) + "/malformed.db";
        { std::ofstream output(invalidPath); output << "not a sqlite database"; }
        Reject([&] { loaded.Load(invalidPath); }); Check(loaded.Size() == 2);
        auto changed = [&](const char* sql)
        {
            const auto changedPath = std::string(argv[1]) + "/changed.db";
            { std::ifstream source(path,std::ios::binary); std::ofstream dest(changedPath,std::ios::binary | std::ios::trunc); dest << source.rdbuf(); }
            sqlite3* db = nullptr; Check(sqlite3_open(changedPath.c_str(),&db) == SQLITE_OK);
            Check(sqlite3_exec(db,sql,nullptr,nullptr,nullptr) == SQLITE_OK); sqlite3_close(db);
            Reject([&] { loaded.Load(changedPath); }); Check(loaded.Size() == 2);
        };
        for (const auto* sql : {"PRAGMA application_id=0", "PRAGMA user_version=99",
            "UPDATE capture SET value='Linux' WHERE key='platform'", "UPDATE events SET pid=456 WHERE id=1",
            "UPDATE events SET timestamp=0 WHERE id=1", "UPDATE events SET result=NULL WHERE id=1",
            "UPDATE events SET duration=1 WHERE id=1", "UPDATE events SET details='forged' WHERE id=1",
            "UPDATE events SET data=x'00' WHERE id=1", "CREATE VIEW evil AS SELECT * FROM events",
            "CREATE TRIGGER evil AFTER INSERT ON events BEGIN DELETE FROM events; END"}) changed(sql);
        NativeStorage bounded; bounded.Initialize({}); bounded.Limits(1,1024 * 1024);
        Check(bounded.Store(Telemetry(event)) && bounded.Size() == 1);
        Reject([&] { bounded.Store(Telemetry(event)); }); Check(bounded.Size() == 1);
        bounded.Clear(); Reject([&] { bounded.StoreMany({Telemetry(event),Telemetry(second)}); }); Check(bounded.Size() == 0);
        Check(bounded.Store(Telemetry(second)) && bounded.Size() == 1);
        bounded.Clear(); bounded.Limits(10,1); Reject([&] { bounded.Store(Telemetry(event)); }); Check(bounded.Size() == 0);
        Reject([&] { bounded.Limits(0,1); }); Reject([&] { bounded.Limits(1,268435457); });
        std::size_t visited = 0; loaded.Visit({},{},[&](const ITelemetry& row) { Check(row.native != nullptr); ++visited; }); Check(visited == 2);
        auto wide = event; wide.stack.assign(32,0x1234); wide.symbols.assign(32,std::string(2600,'S'));
        wide.command.assign(4096,static_cast<char>(255));
        for (auto& argument : wide.arguments) argument.text = std::string(4096,static_cast<char>(255));
        NativeStorage large; large.Initialize({}); Check(large.Store(Telemetry(wide)));
        const auto largePath = std::string(argv[1]) + "/large-row.db"; Check(large.Export({1,"large"},largePath));
        NativeStorage largeReplay; largeReplay.Initialize({}); Check(std::get<1>(largeReplay.Load(largePath)) == "large");
        Check(Encode(*largeReplay.QueryByPids({})[0].native) == Encode(wide));
        NativeStorage concurrent; concurrent.Initialize({}); std::atomic<bool> done{false}; std::exception_ptr failure;
        std::thread producer([&] { try { for (unsigned index = 0; index < 200; ++index) concurrent.Store(Telemetry(event)); }
            catch (...) { failure = std::current_exception(); } done = true; });
        while (!done) (void)concurrent.QueryByEventsinPage({}, 0, 10, ScreenConfiguration::time, true);
        producer.join(); if (failure) std::rethrow_exception(failure); Check(concurrent.Size() == 200);
        Check(loaded.Clear() && loaded.Size() == 0);
        std::cout << "PASS: " << checks << " FreeBSD application event/storage checks\n";
    }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
