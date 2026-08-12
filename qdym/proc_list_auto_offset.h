#ifndef PROC_LIST_AUTO_OFFSET_H
#define PROC_LIST_AUTO_OFFSET_H

#include "proc_root_auto_offset.h"

/* Additional offsets needed for process listing */

static unsigned long g_offset_task_real_parent;
static unsigned long g_offset_task_start_time;
static unsigned long g_offset_task_state;
static unsigned long g_offset_task_flags;
static unsigned long g_offset_task_utime;
static unsigned long g_offset_task_stime;
static unsigned long g_offset_task_prio;

#define TASK_REAL_PARENT(p) (*(struct task_struct **)((unsigned char *)(p) + g_offset_task_real_parent))
#define TASK_START_TIME(p)  (*(unsigned long long *)((unsigned char *)(p) + g_offset_task_start_time))
#define TASK_STATE(p)       (*(volatile long *)((unsigned char *)(p) + g_offset_task_state))
#define TASK_FLAGS(p)       (*(unsigned int *)((unsigned char *)(p) + g_offset_task_flags))
#define TASK_PRIO(p)        (*(int *)((unsigned char *)(p) + g_offset_task_prio))

static int __detect_proc_list_offsets(void)
{
    struct task_struct *cur;
    unsigned char *base;
    unsigned long i;
    size_t scan_size = 4096;

    cur = GET_CURRENT();
    if (!cur) return -1;
    base = (unsigned char *)cur;

    /* real_parent */
    for (i = 0; i < scan_size; i += sizeof(void *)) {
        struct task_struct **pp = (struct task_struct **)(base + i);
        if (*pp == cur->real_parent && cur->real_parent &&
            i != g_offset_task_mm && i != g_offset_task_parent) {
            g_offset_task_real_parent = i;
            pr_info("proc_list_auto_offset: real_parent found at offset %zu\n", i);
            break;
        }
    }

    /* state */
    for (i = 0; i < scan_size; i += sizeof(long)) {
        volatile long *sp = (volatile long *)(base + i);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
        if (*sp == cur->__state) {
#else
        if (*sp == cur->state) {
#endif
            g_offset_task_state = i;
            pr_info("proc_list_auto_offset: state found at offset %zu\n", i);
            break;
        }
    }

    /* flags */
    for (i = 0; i < scan_size; i += sizeof(unsigned int)) {
        unsigned int *fp = (unsigned int *)(base + i);
        if (*fp == cur->flags && i != g_offset_task_pid && i != g_offset_task_tgid) {
            g_offset_task_flags = i;
            pr_info("proc_list_auto_offset: flags found at offset %zu\n", i);
            break;
        }
    }

    /* prio */
    for (i = 0; i < scan_size; i += sizeof(int)) {
        int *pp = (int *)(base + i);
        if (*pp == cur->prio &&
            i != g_offset_task_pid && i != g_offset_task_tgid) {
            g_offset_task_prio = i;
            pr_info("proc_list_auto_offset: prio found at offset %zu\n", i);
            break;
        }
    }

    /* If detection fails, use defaults for 6.1 kernel */
    if (!g_offset_task_tasks)   g_offset_task_tasks   = 0x208;
    if (!g_offset_task_real_parent) g_offset_task_real_parent = 0x220;
    if (!g_offset_task_state)  g_offset_task_state  = 0x08;
    if (!g_offset_task_flags)  g_offset_task_flags  = 0x24;
    if (!g_offset_task_prio)   g_offset_task_prio   = 0x68;

    return 0;
}

#endif
