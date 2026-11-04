/* SPDX-License-Identifier: MIT */
/* Bounded raw user PCs for the existing marked fixture, not symbol resolution. */
dtrace:::BEGIN
/$2 == 0/
{
    trace((uint64_t)$1);
}

syscall:freebsd:getpgid:entry
/pid == $1 && arg0 == 0/
{
    active = 1;
    trace((uint64_t)pid);
    trace((uint64_t)timestamp);
    trace((uint64_t)arg0);
}

syscall:freebsd:getpgid:entry
/pid == $1 && arg0 == pid/
{
    active = 0;
    trace((uint64_t)pid);
    trace((uint64_t)timestamp);
    trace((uint64_t)arg0);
}

syscall:freebsd:openat:entry
/pid == $1 && active/
{
    trace((uint64_t)pid);
    trace((uint64_t)tid);
    trace((uint64_t)timestamp);
    ustack(8);
}

syscall:freebsd:_exit:entry
/pid == $1/
{
    trace((uint64_t)pid);
    trace((uint64_t)arg0);
}

dtrace:::END
{
    trace((uint64_t)$1);
}
