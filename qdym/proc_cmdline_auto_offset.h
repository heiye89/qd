#ifndef PROC_CMDLINE_AUTO_OFFSET_H
#define PROC_CMDLINE_AUTO_OFFSET_H

/* Offsets for reading /proc/cmdline style data directly from kernel image */
/* The kernel command line is stored in 'saved_command_line' */

static unsigned long g_addr_saved_command_line;

static int __detect_cmdline_offsets(void)
{
    g_addr_saved_command_line = lkapi_kallsyms_lookup_name("saved_command_line");
    if (g_addr_saved_command_line) {
        pr_info("proc_cmdline_auto_offset: saved_command_line @ %lx\n",
                g_addr_saved_command_line);
    } else {
        pr_warn("proc_cmdline_auto_offset: saved_command_line not found\n");
        return -1;
    }
    return 0;
}

#endif
