/* SPDX-License-Identifier: MIT */
/* Running-kernel inventory through installed libdtrace/CTF interfaces. */
#include <sys/types.h>
#include <sys/stat.h>

#include <dtrace.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

struct inventory {
    unsigned int entries, returns, arguments, info_failures, type_failures;
    int max_entry, max_return;
};

static int
inspect_probe(dtrace_hdl_t *handle, const dtrace_probedesc_t *probe, void *argument)
{
    struct inventory *inventory = argument;
    dtrace_probeinfo_t info;
    int entry = strcmp(probe->dtpd_name, "entry") == 0;
    if (strcmp(probe->dtpd_provider, "syscall") || strcmp(probe->dtpd_mod, "freebsd") ||
        (!entry && strcmp(probe->dtpd_name, "return")))
        return -1;
    if (entry)
        inventory->entries++;
    else
        inventory->returns++;
    if (dtrace_probe_info(handle, probe, &info) != 0 || info.dtp_argc < 0 ||
        info.dtp_argc > 64 || (info.dtp_argc && info.dtp_argv == NULL)) {
        inventory->info_failures++;
        printf("INFO_ERROR\t%s\t%s\n", probe->dtpd_name, probe->dtpd_func);
        return 0;
    }
    if (entry && info.dtp_argc > inventory->max_entry)
        inventory->max_entry = info.dtp_argc;
    if (!entry && info.dtp_argc > inventory->max_return)
        inventory->max_return = info.dtp_argc;
    printf("PROBE\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
        probe->dtpd_name, probe->dtpd_func, info.dtp_argc,
        dtrace_stability_name(info.dtp_attr.dtat_name),
        dtrace_stability_name(info.dtp_attr.dtat_data),
        dtrace_class_name(info.dtp_attr.dtat_class),
        dtrace_stability_name(info.dtp_arga.dtat_name),
        dtrace_stability_name(info.dtp_arga.dtat_data),
        dtrace_class_name(info.dtp_arga.dtat_class));
    for (int index = 0; index < info.dtp_argc; index++) {
        char type[512];
        const dtrace_typeinfo_t *item = &info.dtp_argv[index];
        if (item->dtt_ctfp == NULL ||
            ctf_type_name(item->dtt_ctfp, item->dtt_type, type, sizeof(type)) == NULL) {
            inventory->type_failures++;
            strcpy(type, "<unresolved>");
        }
        inventory->arguments++;
        printf("ARG\t%s\t%s\t%d\t%d\t%s\n", probe->dtpd_name,
            probe->dtpd_func, index, !!(item->dtt_flags & DTT_FL_USER), type);
    }
    return 0;
}

int
main(void)
{
    struct stat device;
    struct inventory inventory = {0};
    dtrace_probedesc_t filter;
    int error, failed = 0;
    if (stat("/dev/dtrace/dtrace", &device) || !S_ISCHR(device.st_mode)) {
        fprintf(stderr, "DTrace device missing; no module load attempted\n");
        return 1;
    }
    dtrace_hdl_t *handle = dtrace_open(DTRACE_VERSION, 0, &error);
    if (handle == NULL) {
        fprintf(stderr, "dtrace_open: %s\n", dtrace_errmsg(NULL, error));
        return 1;
    }
    const char *queries[] = {"syscall:freebsd:*:entry", "syscall:freebsd:*:return"};
    for (unsigned int index = 0; index < sizeof(queries) / sizeof(*queries); index++) {
        if (dtrace_str2desc(handle, DTRACE_PROBESPEC_NAME, queries[index], &filter) ||
            dtrace_probe_iter(handle, &filter, inspect_probe, &inventory)) {
            fprintf(stderr, "probe inventory: %s\n", dtrace_errmsg(handle, dtrace_errno(handle)));
            failed = 1;
            break;
        }
    }
    dtrace_close(handle);
    printf("AUDIT_END\tentries=%u\treturns=%u\targuments=%u\tmax_entry=%d"
        "\tmax_return=%d\tinfo_failures=%u\ttype_failures=%u\tclosed=1\n",
        inventory.entries, inventory.returns, inventory.arguments, inventory.max_entry,
        inventory.max_return, inventory.info_failures, inventory.type_failures);
    return failed || inventory.info_failures || inventory.type_failures ||
        !inventory.entries || !inventory.returns || ferror(stdout);
}
