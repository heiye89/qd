#ifndef TEST_H
#define TEST_H

/*
 * Test / usage examples for the qdym driver.
 *
 * Usage (after insmod qdym_driver.ko):
 *
 *   # 1. List all processes
 *   ./qdym_test ps
 *
 *   # 2. Hide a process from /proc
 *   ./qdym_test hide 1234
 *
 *   # 3. Unhide a process
 *   ./qdym_test unhide 1234
 *
 *   # 4. Read process virtual memory (hexdump)
 *   ./qdym_test vm_read 5678 0x7f00000000 128
 *
 *   # 5. Write process virtual memory
 *   ./qdym_test vm_write 5678 0x7f00000000 deadbeef
 *
 *   # 6. Get memory maps
 *   ./qdym_test maps 5678
 *
 *   # 7. Get RSS info
 *   ./qdym_test rss 5678
 *
 *   # 8. Get kernel cmdline
 *   ./qdym_test cmdline
 *
 *   # 9. Read physical memory (hexdump)
 *   ./qdym_test phy_read 0x40000000 256
 *
 *   # 10. Write physical memory
 *   ./qdym_test phy_write 0x40000000 deadbeef
 *
 * Compile:
 *   aarch64-linux-gnu-gcc -static -o qdym_test test.h
 *
 * Or cross-compile and push:
 *   aarch64-linux-gnu-gcc -static -o qdym_test test.h
 *   adb push qdym_test /data/local/tmp/
 *   adb shell chmod 755 /data/local/tmp/qdym_test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdint.h>

#include "rwProcMem_module.h"
#include "proc_list.h"
#include "proc_maps.h"
#include "proc_rss.h"
#include "proc_cmdline.h"
#include "phy_mem.h"

#define QDYM_DEVICE "/dev/" DEVICE_NAME

static int fd = -1;

static int open_dev(void)
{
    if (fd >= 0) return 0;
    fd = open(QDYM_DEVICE, O_RDWR);
    if (fd < 0) { perror("open " QDYM_DEVICE); return -1; }
    return 0;
}

static void close_dev(void)
{
    if (fd >= 0) { close(fd); fd = -1; }
}

static void print_hex(const unsigned char *data, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        if (i % 16 == 0) printf("%08zx: ", i);
        printf("%02x ", data[i]);
        if (i % 16 == 15) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}

#ifdef TEST_MAIN

static void cmd_ps(int max)
{
    struct proc_list_args args;
    struct proc_list_entry *ents;
    int i;

    if (max <= 0 || max > PROC_LIST_MAX_ENTRIES) max = 256;
    ents = calloc(max, sizeof(*ents));
    if (!ents) { perror("calloc"); return; }

    args.buf = ents;
    args.max_count = max;
    args.actual_count = 0;

    if (ioctl(fd, QDYM_IOC_GET_PROC_LIST, &args) < 0) {
        perror("ioctl PROC_LIST"); free(ents); return;
    }

    printf("%-6s %-6s %-6s %-16s %s\n", "PID", "TGID", "PPID", "COMM", "STATE");
    for (i = 0; i < args.actual_count; i++) {
        printf("%-6d %-6d %-6d %-16s %ld\n",
               ents[i].pid, ents[i].tgid, ents[i].ppid,
               ents[i].comm, ents[i].state);
    }
    printf("Total: %d\n", args.actual_count);
    free(ents);
}

static void cmd_hide(int pid)
{
    if (ioctl(fd, QDYM_IOC_HIDE_PID, pid) < 0)
        perror("ioctl HIDE_PID");
    else
        printf("PID %d hidden.\n", pid);
}

static void cmd_unhide(int pid)
{
    if (ioctl(fd, QDYM_IOC_UNHIDE_PID, pid) < 0)
        perror("ioctl UNHIDE_PID");
    else
        printf("PID %d unhidden.\n", pid);
}

static void cmd_vm_read(int pid, unsigned long addr, size_t size)
{
    struct vm_mem_args args;
    unsigned char *buf;

    if (!size) size = 256;
    buf = malloc(size);
    if (!buf) { perror("malloc"); return; }

    args.pid = pid; args.addr = addr; args.buf = buf;
    args.size = size; args.bytes_copied = 0;

    if (ioctl(fd, QDYM_IOC_READ_VM, &args) < 0) {
        perror("ioctl READ_VM"); free(buf); return;
    }
    printf("Read %zu bytes from PID %d @ 0x%lx:\n", args.bytes_copied, pid, addr);
    print_hex(buf, args.bytes_copied);
    free(buf);
}

static void cmd_vm_write(int pid, unsigned long addr, const char *hex)
{
    struct vm_mem_args args;
    unsigned char *buf;
    size_t len, i;
    int val;

    len = strlen(hex) / 2;
    if (!len) { fprintf(stderr, "Invalid hex\n"); return; }
    buf = malloc(len);
    if (!buf) { perror("malloc"); return; }
    for (i = 0; i < len; i++) { sscanf(hex + i * 2, "%2x", &val); buf[i] = (unsigned char)val; }

    args.pid = pid; args.addr = addr; args.buf = buf;
    args.size = len; args.bytes_copied = 0;

    if (ioctl(fd, QDYM_IOC_WRITE_VM, &args) < 0) {
        perror("ioctl WRITE_VM"); free(buf); return;
    }
    printf("Wrote %zu bytes to PID %d @ 0x%lx\n", args.bytes_copied, pid, addr);
    free(buf);
}

static void cmd_maps(int pid, int max)
{
    struct proc_maps_args args;
    struct proc_maps_entry *ents;
    int i;
    const char *perm;
    char perms[5];

    if (max <= 0 || max > PROC_MAPS_MAX_ENTRIES) max = 256;
    ents = calloc(max, sizeof(*ents));
    if (!ents) { perror("calloc"); return; }

    args.pid = pid; args.buf = ents;
    args.max_count = max; args.actual_count = 0;

    if (ioctl(fd, QDYM_IOC_GET_MAPS, &args) < 0) {
        perror("ioctl MAPS"); free(ents); return;
    }

    printf("%-16s %-16s %-4s %-8s %s\n", "START", "END", "FLAGS", "OFFSET", "PATH");
    for (i = 0; i < args.actual_count; i++) {
        unsigned long f = ents[i].vm_flags;
        perms[0] = (f & VM_READ)  ? 'r' : '-';
        perms[1] = (f & VM_WRITE) ? 'w' : '-';
        perms[2] = (f & VM_EXEC)  ? 'x' : '-';
        perms[3] = (f & VM_MAYSHARE) ? 's' : 'p';
        perms[4] = '\0';
        printf("%-16lx %-16lx %-4s %-8lx %s\n",
               ents[i].vm_start, ents[i].vm_end, perms,
               ents[i].vm_pgoff, ents[i].path[0] ? ents[i].path : "[anon]");
    }
    printf("Total: %d\n", args.actual_count);
    free(ents);
}

static void cmd_rss(int pid)
{
    struct proc_rss_args args;

    args.pid = pid;
    if (ioctl(fd, QDYM_IOC_GET_RSS, &args) < 0) {
        perror("ioctl RSS"); return;
    }
    printf("PID %d:\n", pid);
    printf("  RSS:  %lu KB\n", args.info.rss / 1024);
    printf("  VSS:  %lu KB\n", args.info.vss / 1024);
}

static void cmd_cmdline(void)
{
    struct proc_cmdline_args args;
    args.len = 0;
    if (ioctl(fd, QDYM_IOC_GET_CMDLINE, &args) < 0) {
        perror("ioctl CMDLINE"); return;
    }
    printf("Kernel cmdline: %s\n", args.buf);
}

static void cmd_phy_read(unsigned long addr, size_t size)
{
    struct phy_mem_args args;
    unsigned char *buf;

    if (!size) size = 256;
    buf = malloc(size);
    if (!buf) { perror("malloc"); return; }

    args.addr = addr; args.buf = buf;
    args.size = size; args.bytes_copied = 0;

    if (ioctl(fd, QDYM_IOC_READ_PHY_MEM, &args) < 0) {
        perror("ioctl READ_PHY"); free(buf); return;
    }
    printf("Read %zu bytes from PA 0x%lx:\n", args.bytes_copied, addr);
    print_hex(buf, args.bytes_copied);
    free(buf);
}

static void cmd_phy_write(unsigned long addr, const char *hex)
{
    struct phy_mem_args args;
    unsigned char *buf;
    size_t len, i;
    int val;

    len = strlen(hex) / 2;
    if (!len) { fprintf(stderr, "Invalid hex\n"); return; }
    buf = malloc(len);
    if (!buf) { perror("malloc"); return; }
    for (i = 0; i < len; i++) { sscanf(hex + i * 2, "%2x", &val); buf[i] = (unsigned char)val; }

    args.addr = addr; args.buf = buf;
    args.size = len; args.bytes_copied = 0;

    if (ioctl(fd, QDYM_IOC_WRITE_PHY_MEM, &args) < 0) {
        perror("ioctl WRITE_PHY"); free(buf); return;
    }
    printf("Wrote %zu bytes to PA 0x%lx\n", args.bytes_copied, addr);
    free(buf);
}

static void usage(const char *prog)
{
    printf("qdym_test - Android kernel driver test tool\n\n");
    printf("Usage: %s <cmd> [args...]\n", prog);
    printf("\nCommands:\n");
    printf("  ps [max]                     List processes\n");
    printf("  hide <pid>                   Hide process\n");
    printf("  unhide <pid>                 Unhide process\n");
    printf("  vm_read <pid> <addr> [sz]    Read process virtual memory\n");
    printf("  vm_write <pid> <addr> <hex>  Write process virtual memory\n");
    printf("  maps <pid> [max]             Get process memory maps\n");
    printf("  rss <pid>                    Get process RSS/VSS\n");
    printf("  cmdline                      Get kernel cmdline\n");
    printf("  phy_read <addr> [sz]         Read physical memory\n");
    printf("  phy_write <addr> <hex>       Write physical memory\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) { usage(argv[0]); return 1; }
    if (open_dev() < 0) return 1;

    if (!strcmp(argv[1], "ps"))          cmd_ps(argc >= 3 ? atoi(argv[2]) : 256);
    else if (!strcmp(argv[1], "hide"))   { if (argc < 3) { fprintf(stderr, "Usage: hide <pid>\n"); } else cmd_hide(atoi(argv[2])); }
    else if (!strcmp(argv[1], "unhide")) { if (argc < 3) { fprintf(stderr, "Usage: unhide <pid>\n"); } else cmd_unhide(atoi(argv[2])); }
    else if (!strcmp(argv[1], "vm_read")){
        if (argc < 4) fprintf(stderr, "Usage: vm_read <pid> <addr> [sz]\n");
        else cmd_vm_read(atoi(argv[2]), strtoul(argv[3], NULL, 0), argc >= 5 ? strtoul(argv[4], NULL, 0) : 256);
    }
    else if (!strcmp(argv[1], "vm_write")){
        if (argc < 5) fprintf(stderr, "Usage: vm_write <pid> <addr> <hex>\n");
        else cmd_vm_write(atoi(argv[2]), strtoul(argv[3], NULL, 0), argv[4]);
    }
    else if (!strcmp(argv[1], "maps"))   {
        if (argc < 3) fprintf(stderr, "Usage: maps <pid> [max]\n");
        else cmd_maps(atoi(argv[2]), argc >= 4 ? atoi(argv[3]) : 256);
    }
    else if (!strcmp(argv[1], "rss"))    { if (argc < 3) fprintf(stderr, "Usage: rss <pid>\n"); else cmd_rss(atoi(argv[2])); }
    else if (!strcmp(argv[1], "cmdline")) cmd_cmdline();
    else if (!strcmp(argv[1], "phy_read")){
        if (argc < 3) fprintf(stderr, "Usage: phy_read <addr> [sz]\n");
        else cmd_phy_read(strtoul(argv[2], NULL, 0), argc >= 4 ? strtoul(argv[3], NULL, 0) : 256);
    }
    else if (!strcmp(argv[1], "phy_write")){
        if (argc < 4) fprintf(stderr, "Usage: phy_write <addr> <hex>\n");
        else cmd_phy_write(strtoul(argv[2], NULL, 0), argv[3]);
    }
    else { fprintf(stderr, "Unknown: %s\n", argv[1]); usage(argv[0]); }

    close_dev();
    return 0;
}

#endif /* TEST_MAIN */
#endif /* TEST_H */
