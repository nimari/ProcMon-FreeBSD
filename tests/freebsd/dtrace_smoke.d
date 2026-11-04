/* SPDX-License-Identifier: MIT */
/* Isolated FreeBSD native-ABI experiment; not a ProcMon tracing backend. */
#pragma D option quiet
#pragma D option strsize=256
#pragma D option bufsize=4m
#pragma D option dynvarsize=4m
#pragma D option switchrate=10hz

dtrace:::BEGIN
{
    printf("BEGIN\t%d\n", $target);
}

/* The fixture uses these explicit markers after dropping privileges. */
syscall:freebsd:getpgid:entry
/pid == $target && arg0 == 0/
{
    active = 1;
    printf("START\t%d\t%llu\n", pid, (unsigned long long)timestamp);
}

syscall:freebsd:getpgid:entry
/pid == $target && arg0 == pid/
{
    active = 0;
    printf("STOP\t%d\t%llu\n", pid, (unsigned long long)timestamp);
}

syscall:freebsd:openat:entry
/pid == $target && active/
{
    self->start = timestamp;
    self->a0 = (int)arg0;
    self->a2 = arg2;
    self->path = copyinstr(arg1, 64);
    printf("ENTRY\t%d\t%d\t%s\t%llu\t%d\t%llu\t%s\n",
        pid, tid, probefunc, (unsigned long long)self->start, self->a0,
        (unsigned long long)self->a2, self->path);
}

syscall:freebsd:read:entry,
syscall:freebsd:write:entry
/pid == $target && active/
{
    self->start = timestamp;
    self->a0 = (int)arg0;
    self->a2 = arg2;
    self->path = "-";
    printf("ENTRY\t%d\t%d\t%s\t%llu\t%d\t%llu\t%s\n",
        pid, tid, probefunc, (unsigned long long)self->start, self->a0,
        (unsigned long long)self->a2, self->path);
}

syscall:freebsd:openat:return,
syscall:freebsd:read:return,
syscall:freebsd:write:return
/pid == $target && active/
{
    printf("EVENT\t%d\t%d\t%s\t%llu\t%llu\t%lld\t%d\t%d\t%llu\t%s\n",
        pid, tid, probefunc, (unsigned long long)self->start,
        (unsigned long long)(timestamp - self->start), (long long)arg0,
        errno, self->a0, (unsigned long long)self->a2, self->path);
    self->start = 0;
    self->a0 = 0;
    self->a2 = 0;
    self->path = "";
}

syscall:freebsd:_exit:entry
/pid == $target/
{
    printf("TARGET_EXIT\t%d\t%d\n", pid, (int)arg0);
}

dtrace:::ERROR
{
    printf("FAIL\tDTrace-error\n");
    exit(1);
}

tick-10s
{
    printf("FAIL\ttimeout\n");
    exit(1);
}

dtrace:::END
{
    printf("END\n");
}
