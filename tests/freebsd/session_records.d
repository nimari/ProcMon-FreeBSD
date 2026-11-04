/* SPDX-License-Identifier: MIT */
/* $1 fixture PID; $2 is 0 (normal), 4 (SIGINT), or 5 (SIGTERM). */
#pragma D option strsize=65

dtrace:::BEGIN
{
    trace((uint64_t)$1);
    trace((uint64_t)timestamp);
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
/pid == $1 && active && $2 == 0/
{
    self->start = timestamp;
    self->a0 = (int)arg0;
    self->a2 = arg2;
    self->path = copyinstr(arg1, 64);
    trace((uint64_t)pid);
    trace((uint64_t)tid);
    trace((uint64_t)self->start);
    trace((uint64_t)self->a0);
    trace((uint64_t)self->a2);
    trace(self->path);
}

syscall:freebsd:read:entry,
syscall:freebsd:write:entry
/pid == $1 && active && ($2 == 0 || probefunc == "read")/
{
    self->start = timestamp;
    self->a0 = (int)arg0;
    self->a2 = arg2;
    self->path = "-";
    trace((uint64_t)pid);
    trace((uint64_t)tid);
    trace((uint64_t)self->start);
    trace((uint64_t)self->a0);
    trace((uint64_t)self->a2);
    trace(self->path);
}

syscall:freebsd:openat:return,
syscall:freebsd:read:return,
syscall:freebsd:write:return
/pid == $1 && active && ($2 == 0 || probefunc == "read")/
{
    trace((uint64_t)pid);
    trace((uint64_t)tid);
    trace((uint64_t)self->start);
    trace((uint64_t)(timestamp - self->start));
    trace((uint64_t)arg0);
    trace((uint64_t)errno);
    trace((uint64_t)self->a0);
    trace((uint64_t)self->a2);
    trace(self->path);
    self->start = 0;
    self->a0 = 0;
    self->a2 = 0;
    self->path = "";
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
    trace((uint64_t)timestamp);
}
