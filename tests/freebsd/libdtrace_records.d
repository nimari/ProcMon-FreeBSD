/* SPDX-License-Identifier: MIT */
/* $1 is the gated fixture PID; $2 is 0 (normal), 1 (fault), or 2 (drop). */
#pragma D option strsize=65

dtrace:::BEGIN
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
/pid == $1 && active/
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
/pid == $1 && active/
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

/* Intentional, target-scoped runtime fault to exercise the library handler. */
syscall:freebsd:openat:entry
/pid == $1 && active && $2 == 1/
{
    trace(copyinstr(0));
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
