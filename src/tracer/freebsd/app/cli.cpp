// SPDX-License-Identifier: MIT
#include "../../../common/cli_utils.h"
#include <cstdlib>
namespace CLIUtils
{
void FastExit() { std::exit(1); }
void DisplayUsage(bool shouldExit)
{
    std::cout << "ProcMon FreeBSD 2.2.2.1 - native amd64 DTrace application\n"
        "Usage: procmon [-p PID[,PID...]] [-e syscall[,syscall...]] [-c [FILE]]\n"
        "       procmon -f FILE [--dump] [-p PID...] [-e syscall...]\n"
        "  -h, --help              Show help without tracing privileges\n"
        "  --version               Show port version\n"
        "  -p, --pids LIST          Up to ten live native ELF64 PIDs; default all native PIDs\n"
        "  -e, --events LIST        Native syscall names; default all available native probes\n"
        "  --list-events           List available native calls and argument types (use doas)\n"
        "  -c, --collect [FILE]     Headless capture to a new private FreeBSD SQLite trace\n"
        "  -f, --file FILE          Replay a FreeBSD trace; does not start DTrace\n"
        "  --dump                  With --file, emit typed JSON Lines without curses\n"
        "  --duration-ms MS        Stop live capture after 1..86400000 ms\n"
        "  --max-events N          Live event budget: 1..1000000 (default 100000)\n"
        "  --max-bytes N           Live payload budget: 1..268435456 (default 67108864)\n"
        "  --no-strings            Keep raw pointer arguments; skip bounded path snapshots\n"
        "  --no-buffers            Skip bounded read/write/socket buffer snapshots\n"
        "  --no-stacks             Skip bounded user stacks/symbol work\n"
        "  -l, --log FILE          Debug log destination\n"
        "  -s, --storageEngine sql SQLite storage (default)\n"
        "Live capture requires doas and an available DTrace syscall provider.\n"
        "Selected targets stop on exit; exec ends identity-scoped capture as failure.\n"
        "Ctrl-C/SIGTERM stop and drain capture; targets are never terminated.\n"
        "TUI: arrows/page keys, Enter details, F1 help, F2 sort, F3 search, F4 filter,\n"
        "     F5 pause/resume, F6 export to a new file, F8 statistics, q/F9 quit.\n"
        "Paths: up to 256 bytes; buffers: up to 32 bytes; user stacks: up to 16 PCs.\n"
        "Raw arguments retain all advertised positions (up to eight); unavailable\n"
        "snapshots/symbols and incomplete/error/drop conditions remain explicit.\n"
        "FreeBSD trace files are platform/version tagged; Linux traces are rejected.\n"
        "Exit: 0 success, 1 capture/storage failure, 2 usage, 130/143 signal stop.\n";
    if (shouldExit) std::exit(2);
}
}
