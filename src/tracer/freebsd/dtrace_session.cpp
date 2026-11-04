// SPDX-License-Identifier: MIT
#include "dtrace_session.h"

#if !defined(__FreeBSD__) || !defined(__amd64__)
#error "DTrace session currently targets FreeBSD amd64 only"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <dtrace.h>

#include <cerrno>
#include <climits>
#include <cstring>
#include <exception>
#include <limits>
#include <stdexcept>
#include <utility>

namespace procmon::freebsd
{

struct DTraceSession::Impl
{
    dtrace_hdl_t* handle = nullptr;
    SessionStatus status;
    SessionOptions options;
    SessionBatch pending;
    std::size_t batchBytes = 0, batchRecords = 0;
    std::exception_ptr callbackException;

    ~Impl() { Close(); }

    void Fail(const std::string& message)
    {
        status.failed = true;
        if (status.diagnostic.empty())
            status.diagnostic = message;
    }

    void LibraryFailure(const char* stage)
    {
        const char* detail = dtrace_errmsg(handle, dtrace_errno(handle));
        Fail(std::string(stage) + ": " + (detail ? detail : "unknown library error"));
    }

    void Charge(std::size_t amount)
    {
        if (amount > options.maximumBatchBytes - batchBytes)
            throw std::runtime_error("batch byte limit exceeded");
        batchBytes += amount;
    }

    static void Add(std::uint64_t& counter, std::uint64_t amount)
    {
        if (amount > std::numeric_limits<std::uint64_t>::max() - counter)
            throw std::overflow_error("session counter overflow");
        counter += amount;
    }

    static int Probe(const dtrace_probedata_t* data, void* argument) noexcept
    {
        auto& self = *static_cast<Impl*>(argument);
        try
        {
            if (data == nullptr || data->dtpda_pdesc == nullptr || data->dtpda_edesc == nullptr)
                throw std::runtime_error("missing probe descriptor");
            const auto& description = *data->dtpda_edesc;
            if (description.dtepd_nrecs < 0)
                throw std::runtime_error("negative record count");
            auto recordCount = static_cast<std::size_t>(description.dtepd_nrecs);
            if (self.pending.probes.size() >= self.options.maximumBatchProbes ||
                recordCount > self.options.maximumBatchRecords - self.batchRecords)
                throw std::runtime_error("batch probe/record limit exceeded");
            const auto& source = *data->dtpda_pdesc;
            CapturedProbe probe;
            self.Charge(std::strlen(source.dtpd_provider) + std::strlen(source.dtpd_mod) +
                std::strlen(source.dtpd_func) + std::strlen(source.dtpd_name));
            probe.provider = source.dtpd_provider;
            probe.module = source.dtpd_mod;
            probe.function = source.dtpd_func;
            probe.name = source.dtpd_name;
            probe.cpu = data->dtpda_cpu;
            probe.records.reserve(recordCount);
            for (std::size_t index = 0; index < recordCount; ++index)
            {
                const auto& record = description.dtepd_rec[index];
                if (record.dtrd_offset > description.dtepd_size ||
                    record.dtrd_size > description.dtepd_size - record.dtrd_offset ||
                    (record.dtrd_size && data->dtpda_data == nullptr))
                    throw std::runtime_error("invalid record payload bounds");
                self.Charge(record.dtrd_size);
                CapturedRecord copy;
                copy.action = record.dtrd_action;
                copy.argument = record.dtrd_arg;
                copy.alignment = record.dtrd_alignment;
                if (record.dtrd_size)
                {
                    const auto* start = reinterpret_cast<const std::uint8_t*>(data->dtpda_data) +
                        record.dtrd_offset;
                    copy.bytes.assign(start, start + record.dtrd_size);
                }
                probe.records.push_back(std::move(copy));
            }
            self.batchRecords += recordCount;
            self.pending.probes.push_back(std::move(probe));
            Add(self.status.probes, 1);
            return DTRACE_CONSUME_THIS;
        }
        catch (...)
        {
            self.callbackException = std::current_exception();
            return DTRACE_CONSUME_ABORT;
        }
    }

    static int Record(const dtrace_probedata_t*, const dtrace_recdesc_t* record,
        void* argument) noexcept
    {
        auto& self = *static_cast<Impl*>(argument);
        try
        {
            if (record != nullptr)
                Add(record->dtrd_size ? self.status.dataRecords : self.status.zeroRecords, 1);
            // Suppress all library rendering, including symbol/stack formatting.
            return record ? DTRACE_CONSUME_NEXT : DTRACE_CONSUME_THIS;
        }
        catch (...)
        {
            self.callbackException = std::current_exception();
            return DTRACE_CONSUME_ABORT;
        }
    }

    int Notice(NoticeKind kind, int detail, std::uint64_t count, const char* message) noexcept
    {
        try
        {
            Add(kind == NoticeKind::Drop ? status.drops : status.runtimeErrors, count);
            if (pending.notices.size() >= options.maximumBatchNotices)
                throw std::runtime_error("batch notice limit exceeded");
            Charge(message ? std::strlen(message) : 0);
            pending.notices.push_back({kind, detail, count, message ? message : ""});
            return DTRACE_HANDLE_OK;
        }
        catch (...)
        {
            callbackException = std::current_exception();
            return DTRACE_HANDLE_ABORT;
        }
    }

    static int Error(const dtrace_errdata_t* data, void* argument) noexcept
    {
        return static_cast<Impl*>(argument)->Notice(NoticeKind::RuntimeError,
            data->dteda_fault, 1, data->dteda_msg);
    }

    static int Drop(const dtrace_dropdata_t* data, void* argument) noexcept
    {
        return static_cast<Impl*>(argument)->Notice(NoticeKind::Drop,
            data->dtdda_kind, data->dtdda_drops, data->dtdda_msg);
    }

    bool CheckCallback()
    {
        if (!callbackException)
            return true;
        try { std::rethrow_exception(callbackException); }
        catch (const std::bad_alloc&) { throw; }
        catch (const std::exception& error) { Fail(std::string("callback: ") + error.what()); }
        catch (...) { Fail("unknown callback exception"); }
        return false;
    }

    void Close() noexcept
    {
        if (handle != nullptr)
        {
            if (status.started && !status.stopped)
            {
                if (dtrace_stop(handle) == 0)
                    status.stopped = true;
                else
                    status.failed = true;
            }
            if (status.started && !status.drained)
                status.discarded = true;
            dtrace_close(handle);
            handle = nullptr;
        }
        status.closed = true;
    }

    SessionBatch Take(PollOutcome outcome)
    {
        pending.outcome = outcome;
        SessionBatch result = std::move(pending);
        pending = {};
        batchBytes = batchRecords = 0;
        return result;
    }
};

DTraceSession::DTraceSession() : impl(std::make_unique<Impl>()) {}
DTraceSession::~DTraceSession() = default;

bool DTraceSession::Start(const std::string& program, const std::vector<std::string>& arguments,
    const SessionOptions& options)
{
    auto& self = *impl;
    if (self.status.attempted || self.status.closed)
    {
        self.Fail("session is single-use");
        return false;
    }
    self.status.attempted = true;
    try
    {
        self.options = options;
        if (program.empty() || program.find('\0') != std::string::npos ||
            arguments.size() >= INT_MAX || options.maximumBatchBytes == 0 ||
            options.maximumBatchProbes == 0 || options.maximumBatchRecords == 0 ||
            options.maximumBatchNotices == 0 || options.bufferSize.find('\0') != std::string::npos ||
            options.dynamicVariableSize.find('\0') != std::string::npos)
        {
            self.Fail("invalid program, arguments or session options");
            self.Close();
            return false;
        }
        std::vector<std::string> macros{"procmon-freebsd-session"};
        for (const auto& argument : arguments)
        {
            if (argument.find('\0') != std::string::npos)
            {
                self.Fail("embedded NUL in macro argument");
                self.Close();
                return false;
            }
            macros.push_back(argument);
        }
        std::vector<char*> macroPointers;
        for (auto& argument : macros)
            macroPointers.push_back(argument.data());
        struct stat device{};
        if (stat("/dev/dtrace/dtrace", &device) != 0 || !S_ISCHR(device.st_mode))
        {
            self.Fail("DTrace character device unavailable; no module load attempted");
            self.Close();
            return false;
        }
        int error = 0;
        self.handle = dtrace_open(DTRACE_VERSION, 0, &error);
        if (self.handle == nullptr)
        {
            const char* detail = dtrace_errmsg(nullptr, error);
            self.Fail(std::string("open: ") + (detail ? detail : "unknown library error"));
            self.Close();
            return false;
        }
        self.status.opened = true;
        if (dtrace_handle_err(self.handle, Impl::Error, &self) ||
            dtrace_handle_drop(self.handle, Impl::Drop, &self) ||
            dtrace_setopt(self.handle, "bufsize", options.bufferSize.c_str()) ||
            dtrace_setopt(self.handle, "dynvarsize", options.dynamicVariableSize.c_str()) ||
            dtrace_setopt(self.handle, "switchrate", "100hz") ||
            dtrace_setopt(self.handle, "statusrate", "100hz"))
            self.LibraryFailure("setup");
        if (!self.status.failed)
        {
            auto* compiled = dtrace_program_strcompile(self.handle, program.c_str(),
                DTRACE_PROBESPEC_NAME, 0, static_cast<int>(macroPointers.size()), macroPointers.data());
            if (compiled == nullptr)
                self.LibraryFailure("compile");
            else if (dtrace_program_exec(self.handle, compiled, nullptr) != 0)
                self.LibraryFailure("enable");
            else if (dtrace_go(self.handle) != 0)
                self.LibraryFailure("go");
            else
                self.status.started = true;
        }
        self.CheckCallback();
        if (self.status.failed)
            self.Close();
        return !self.status.failed;
    }
    catch (...)
    {
        self.status.failed = true;
        self.Close();
        throw;
    }
}

SessionBatch DTraceSession::Poll()
{
    auto& self = *impl;
    try
    {
        if (self.status.failed || self.status.closed || !self.status.started)
        {
            self.Fail("poll requires a healthy started session");
            return self.Take(PollOutcome::Error);
        }
        if (self.status.drained)
            return self.Take(PollOutcome::Done);
        auto outcome = dtrace_work(self.handle, nullptr, Impl::Probe, Impl::Record, &self);
        if (!self.CheckCallback())
            return self.Take(PollOutcome::Error);
        if (outcome == DTRACE_WORKSTATUS_ERROR)
        {
            self.LibraryFailure("work");
            return self.Take(PollOutcome::Error);
        }
        if (outcome == DTRACE_WORKSTATUS_DONE)
        {
            self.status.stopped = self.status.drained = true;
            return self.Take(PollOutcome::Done);
        }
        return self.Take(PollOutcome::Okay);
    }
    catch (...)
    {
        self.status.failed = true;
        self.Close();
        throw;
    }
}

bool DTraceSession::Stop()
{
    auto& self = *impl;
    try
    {
        if (self.status.stopped)
            return true;
        if (self.handle == nullptr || !self.status.started)
        {
            self.Fail("stop requires a started session");
            return false;
        }
        if (dtrace_stop(self.handle) != 0)
        {
            self.LibraryFailure("stop");
            return false;
        }
        self.status.stopped = true;
        self.CheckCallback();
        return !self.status.failed;
    }
    catch (...)
    {
        self.status.failed = true;
        self.Close();
        throw;
    }
}

void DTraceSession::Close() noexcept { impl->Close(); }
const SessionStatus& DTraceSession::Status() const noexcept { return impl->status; }

} // namespace procmon::freebsd
