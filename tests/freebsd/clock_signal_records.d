/* SPDX-License-Identifier: MIT */
/* $1 is the fixture PID; $2 is 3 (clock), 4 (SIGINT), or 5 (SIGTERM). */
dtrace:::BEGIN
{
    trace((uint64_t)$1);
}

syscall:freebsd:getpgid:entry
/pid == $1 && $2 == 3/
{
    self->clock_arg = (int)arg0;
    trace((uint64_t)pid);
    trace((uint64_t)tid);
    trace((uint64_t)timestamp);
    trace((uint64_t)self->clock_arg);
}

syscall:freebsd:getpgid:return
/pid == $1 && $2 == 3/
{
    trace((uint64_t)pid);
    trace((uint64_t)tid);
    trace((uint64_t)timestamp);
    trace((uint64_t)arg0);
    trace((uint64_t)errno);
    trace((uint64_t)self->clock_arg);
    self->clock_arg = 0;
}

syscall:freebsd:getpgid:entry
/pid == $1 && $2 >= 4 && arg0 == 0/
{
    active = 1;
    trace((uint64_t)pid);
    trace((uint64_t)timestamp);
    trace((uint64_t)arg0);
}

syscall:freebsd:read:entry
/pid == $1 && $2 >= 4 && active/
{
    trace((uint64_t)pid);
    trace((uint64_t)tid);
    trace((uint64_t)timestamp);
    trace((uint64_t)(int)arg0);
    trace((uint64_t)arg2);
}

syscall:freebsd:read:return
/pid == $1 && $2 >= 4 && active/
{
    trace((uint64_t)pid);
    trace((uint64_t)tid);
    trace((uint64_t)timestamp);
    trace((uint64_t)arg0);
    trace((uint64_t)errno);
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
