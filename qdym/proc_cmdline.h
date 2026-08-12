#ifndef PROC_CMDLINE_H
#define PROC_CMDLINE_H

#include "linux_kernel_api.h"
#include "proc_cmdline_auto_offset.h"

#define PROC_CMDLINE_MAX_LEN 4096

struct proc_cmdline_args {
    char buf[PROC_CMDLINE_MAX_LEN];
    int len;
};

static int proc_cmdline_get(struct proc_cmdline_args __user *uargs)
{
    struct proc_cmdline_args args;
    char *cmdline;
    int len;

    if (!g_addr_saved_command_line) {
        strncpy(args.buf, "[unavailable]", sizeof(args.buf));
        args.len = strlen(args.buf);
        goto out;
    }

    cmdline = (char *)PHYS_TO_VIRT(g_addr_saved_command_line);
    if (!cmdline) {
        strncpy(args.buf, "[unavailable]", sizeof(args.buf));
        args.len = strlen(args.buf);
        goto out;
    }

    len = strnlen(cmdline, PROC_CMDLINE_MAX_LEN - 1);
    if (len >= PROC_CMDLINE_MAX_LEN)
        len = PROC_CMDLINE_MAX_LEN - 1;
    memcpy(args.buf, cmdline, len);
    args.buf[len] = '\0';
    args.len = len;

out:
    if (copy_to_user(uargs->buf, args.buf, sizeof(args.buf)))
        return -EFAULT;
    if (copy_to_user(&uargs->len, &args.len, sizeof(args.len)))
        return -EFAULT;

    return 0;
}

#endif
