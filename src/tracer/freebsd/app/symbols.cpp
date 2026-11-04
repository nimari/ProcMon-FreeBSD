// SPDX-License-Identifier: MIT
#include "symbols.h"
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <libprocstat.h>
#include <gelf.h>
#include <fcntl.h>
#include <unistd.h>
#include <cxxabi.h>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <sstream>

namespace procmon::freebsd::app
{
struct NativeSymbols::Impl
{
    struct Mapping { std::uint64_t start, end, offset, inode; std::string path; };
    struct Process { std::uint64_t seconds, microseconds, image; std::vector<Mapping> maps; };
    struct Symbol { std::uint64_t address, size; std::string name; };
    struct Image { std::uint64_t inode; std::vector<GElf_Phdr> segments; std::vector<Symbol> symbols; };
    struct procstat* processStatus = nullptr;
    std::map<std::uint64_t,Process> processes;
    std::map<std::string,Image> images;
    Impl() { elf_version(EV_CURRENT); processStatus = procstat_open_sysctl(); }
    ~Impl() { if (processStatus) procstat_close(processStatus); }
    void Snapshot(std::uint64_t pid)
    {
        if (!processStatus || pid > INT32_MAX) return;
        unsigned count = 0; auto* process = procstat_getprocs(processStatus,KERN_PROC_PID,static_cast<int>(pid),&count);
        if (!process || count != 1) { if (process) procstat_freeprocs(processStatus,process); return; }
        timeval boot{}; std::size_t size = sizeof(boot);
        if (sysctlbyname("kern.boottime",&boot,&size,nullptr,0) || size != sizeof(boot)) { procstat_freeprocs(processStatus,process); return; }
        auto seconds = process->ki_start.tv_sec - boot.tv_sec, micros = process->ki_start.tv_usec - boot.tv_usec;
        if (micros < 0) { --seconds; micros += 1000000; }
        Process snapshot{static_cast<std::uint64_t>(seconds),static_cast<std::uint64_t>(micros),reinterpret_cast<std::uintptr_t>(process->ki_textvp),{}};
        auto* maps = procstat_getvmmap(processStatus,process,&count);
        if (maps && count <= 65536)
            for (unsigned index = 0; index < count; ++index)
                if (snapshot.maps.size() < 256 && (maps[index].kve_protection & 4) && maps[index].kve_path[0] == '/' && maps[index].kve_end > maps[index].kve_start)
                    snapshot.maps.push_back({maps[index].kve_start,maps[index].kve_end,maps[index].kve_offset,maps[index].kve_vn_fileid,maps[index].kve_path});
        if (maps) procstat_freevmmap(processStatus,maps); procstat_freeprocs(processStatus,process);
        if (processes.size() >= 64) processes.clear(); processes[pid] = std::move(snapshot);
    }
    const Image* ReadImage(const Mapping& mapping)
    {
        auto cached = images.find(mapping.path);
        if (cached != images.end() && cached->second.inode == mapping.inode) return &cached->second;
        if (images.size() >= 32) images.clear();
        int fd = open(mapping.path.c_str(),O_RDONLY | O_CLOEXEC | O_NOFOLLOW); if (fd < 0) return nullptr;
        struct stat info{};
        if (fstat(fd,&info) || !S_ISREG(info.st_mode) || static_cast<std::uint64_t>(info.st_ino) != mapping.inode || info.st_size > 536870912)
        { close(fd); return nullptr; }
        Elf* elf = elf_begin(fd,ELF_C_READ,nullptr); Image image{mapping.inode,{},{}}; std::size_t symbolBytes = 0;
        if (elf)
        {
            GElf_Ehdr header{}; std::size_t count = 0;
            if (gelf_getehdr(elf,&header) && header.e_machine == EM_X86_64 && elf_getphdrnum(elf,&count) == 0 && count < 1024)
            {
                for (std::size_t index = 0; index < count; ++index)
                { GElf_Phdr segment{}; if (gelf_getphdr(elf,static_cast<int>(index),&segment) && segment.p_type == PT_LOAD) image.segments.push_back(segment); }
                Elf_Scn* section = nullptr; unsigned sections = 0;
                while ((section = elf_nextscn(elf,section)) && ++sections < 8192)
                {
                    GElf_Shdr sh{}; if (!gelf_getshdr(section,&sh) || (sh.sh_type != SHT_SYMTAB && sh.sh_type != SHT_DYNSYM) || !sh.sh_entsize) continue;
                    Elf_Data* data = elf_getdata(section,nullptr); if (!data || sh.sh_size / sh.sh_entsize > 1000000) continue;
                    for (std::uint64_t index = 0; index < sh.sh_size / sh.sh_entsize && image.symbols.size() < 1000000 && symbolBytes < 2 * 1024 * 1024; ++index)
                    {
                        GElf_Sym symbol{}; if (!gelf_getsym(data,static_cast<int>(index),&symbol) || !symbol.st_value ||
                            (GELF_ST_TYPE(symbol.st_info) != STT_FUNC && GELF_ST_TYPE(symbol.st_info) != STT_GNU_IFUNC)) continue;
                        const char* name = elf_strptr(elf,sh.sh_link,symbol.st_name);
                        if (name && strnlen(name,4096) < 4096)
                        { image.symbols.push_back({symbol.st_value,symbol.st_size,name}); symbolBytes += sizeof(Symbol) + std::strlen(name); }
                    }
                }
            }
            elf_end(elf);
        }
        close(fd);
        std::sort(image.symbols.begin(),image.symbols.end(),[](const auto& a,const auto& b) { return a.address < b.address; });
        return &images.insert_or_assign(mapping.path,std::move(image)).first->second;
    }
    std::string Symbolize(const Mapping& map, std::uint64_t address)
    {
        std::ostringstream result; result << Escape(map.path) << "!";
        const auto offset = address - map.start + map.offset; auto* image = ReadImage(map);
        if (image)
        {
            for (const auto& segment : image->segments)
            {
                if (offset < segment.p_offset || offset - segment.p_offset >= segment.p_filesz) continue;
                const auto relative = segment.p_vaddr + offset - segment.p_offset;
                auto found = std::upper_bound(image->symbols.begin(),image->symbols.end(),relative,[](auto value,const auto& symbol) { return value < symbol.address; });
                if (found != image->symbols.begin())
                {
                    --found;
                    if (found->size && relative - found->address < found->size)
                    {
                        int status = 0; char* demangled = found->name.rfind("_Z",0) == 0 ? abi::__cxa_demangle(found->name.c_str(),nullptr,nullptr,&status) : nullptr;
                        result << Escape(status == 0 && demangled ? demangled : found->name);
                        std::free(demangled); result << "+0x" << std::hex << relative - found->address; return result.str();
                    }
                }
            }
        }
        result << "+0x" << std::hex << offset << " [symbol unavailable]"; return result.str();
    }
};
NativeSymbols::NativeSymbols(): impl(std::make_unique<Impl>()) {}
NativeSymbols::~NativeSymbols() = default;
void NativeSymbols::Prime(std::uint64_t pid)
{
    impl->Snapshot(pid); auto found = impl->processes.find(pid);
    if (found != impl->processes.end()) for (const auto& map : found->second.maps) (void)impl->ReadImage(map);
}
void NativeSymbols::Resolve(CapturedEvent& captured)
{
    auto& event = captured.data; if (event.stack.empty()) return;
    auto found = impl->processes.find(event.pid);
    auto matches = [&] { return found != impl->processes.end() && found->second.seconds == captured.birthSeconds &&
        found->second.microseconds == captured.birthMicroseconds && found->second.image == captured.imageAddress; };
    if (!matches()) { impl->Snapshot(event.pid); found = impl->processes.find(event.pid); }
    event.symbols.clear();
    for (auto address : event.stack)
    {
        std::string symbol = "[mapping unavailable for captured process/image]";
        if (matches())
            for (const auto& map : found->second.maps) if (address >= map.start && address < map.end)
            { symbol = impl->Symbolize(map,address); break; }
        if (symbol.size() > 4096) { symbol.resize(4080); symbol += " [limit]"; }
        event.symbols.push_back(std::move(symbol));
    }
}
} // namespace procmon::freebsd::app
