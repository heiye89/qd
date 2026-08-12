#ifndef PROC_ROOT_AUTO_OFFSET_H
#define PROC_ROOT_AUTO_OFFSET_H

#include "linux_kernel_api.h"
#include "ver_control.h"

/* Detected offsets for struct task_struct */
static unsigned long g_offset_task_pid;
static unsigned long g_offset_task_tgid;
static unsigned long g_offset_task_comm;
static unsigned long g_offset_task_mm;
static unsigned long g_offset_task_tasks;
static unsigned long g_offset_task_thread_group;
static unsigned long g_offset_task_parent;
static unsigned long g_offset_task_cred;

/* Size of struct task_struct (estimated) */
static unsigned long g_size_task_struct;

#define TASK_PID(p)       (*(pid_t      *)((unsigned char *)(p) + g_offset_task_pid))
#define TASK_TGID(p)      (*(pid_t      *)((unsigned char *)(p) + g_offset_task_tgid))
#define TASK_COMM(p)      ((char *)((unsigned char *)(p) + g_offset_task_comm))
#define TASK_MM(p)        (*(struct mm_struct **)((unsigned char *)(p) + g_offset_task_mm))
#define TASK_TASKS(p)     ((struct list_head *)((unsigned char *)(p) + g_offset_task_tasks))
#define TASK_THREAD_GROUP(p) ((struct list_head *)((unsigned char *)(p) + g_offset_task_thread_group))
#define TASK_PARENT(p)    (*(struct task_struct **)((unsigned char *)(p) + g_offset_task_parent))
#define TASK_CRED(p)      (*(struct cred **)((unsigned char *)(p) + g_offset_task_cred))

static const char __auto_offset_marker[] = "QDYM_AUTO_OFFSET_SCAN";

static int __detect_task_offsets(void)
{
    struct task_struct *cur;
    unsigned char *base;
    unsigned long i;
    int found_comm = 0;
    size_t comm_offset = 0;
    size_t scan_size = 4096;

    cur = GET_CURRENT();
    if (!cur) {
        pr_err("proc_root_auto_offset: GET_CURRENT() returned NULL\n");
        return -1;
    }

    /* Set a known comm value to scan for */
    get_task_comm((char *)cur->comm, cur);
    base = (unsigned char *)cur;

    /* Scan task_struct for the comm field (we know its value from get_task_comm) */
    for (i = 0; i < scan_size; i += sizeof(void *)) {
        if (i + TASK_COMM_LEN > scan_size)
            break;
        if (memcmp(base + i, cur->comm, TASK_COMM_LEN) == 0) {
            comm_offset = i;
            found_comm = 1;
            pr_info("proc_root_auto_offset: comm found at offset %zu\n", comm_offset);
            break;
        }
    }

    if (!found_comm) {
        pr_err("proc_root_auto_offset: failed to find comm in task_struct\n");
        return -1;
    }

    g_offset_task_comm = comm_offset;

    /* Scan around comm for other fields */
    for (i = 0; i < scan_size; i += sizeof(int)) {
        pid_t *pp = (pid_t *)(base + i);

        /* pid: the task's own PID */
        if (i != comm_offset && *pp == cur->pid) {
            g_offset_task_pid = i;
            pr_info("proc_root_auto_offset: pid found at offset %zu (value=%d)\n",
                    i, cur->pid);
            break;
        }
    }

    /* tgid: thread group ID */
    for (i = 0; i < scan_size; i += sizeof(int)) {
        pid_t *pp = (pid_t *)(base + i);
        if (i != g_offset_task_pid && *pp == cur->tgid) {
            g_offset_task_tgid = i;
            pr_info("proc_root_auto_offset: tgid found at offset %zu (value=%d)\n",
                    i, cur->tgid);
            break;
        }
    }

    /* mm: pointer to mm_struct */
    for (i = 0; i < scan_size; i += sizeof(void *)) {
        struct mm_struct **mp = (struct mm_struct **)(base + i);
        if (*mp == cur->mm && cur->mm) {
            g_offset_task_mm = i;
            pr_info("proc_root_auto_offset: mm found at offset %zu (ptr=%px)\n",
                    i, cur->mm);
            break;
        }
    }

    /* tasks: list_head - difficult to detect automatically, use known offsets */
    /* For 5.x+ kernels, 'tasks' is typically at offset 0x1a0-0x218 range */
    /* We'll use a heuristic: find a list_head that links back into the task list */
    {
        struct task_struct *next_one;
        unsigned long next_addr;
        struct list_head *candidate;

        /* Try to find tasks by checking list_head pointers */
        for (i = 0; i < scan_size - sizeof(struct list_head); i += 8) {
            struct list_head *lh = (struct list_head *)(base + i);
            if (lh->next && lh->prev &&
                (unsigned long)lh->next > 0xffff000000000000ULL &&
                (unsigned long)lh->prev > 0xffff000000000000ULL) {

                next_addr = (unsigned long)lh->next;
                next_one = (struct task_struct *)(next_addr - i);

                if (next_one != cur &&
                    (unsigned long)next_one > 0xffff000000000000ULL) {
                    g_offset_task_tasks = i;
                    pr_info("proc_root_auto_offset: tasks found at offset %zu\n", i);
                    break;
                }
            }
        }
    }

    /* parent: pointer to parent task */
    for (i = 0; i < scan_size; i += sizeof(void *)) {
        struct task_struct **pp = (struct task_struct **)(base + i);
        if (*pp == cur->parent && cur->parent &&
            i != g_offset_task_mm) {
            g_offset_task_parent = i;
            pr_info("proc_root_auto_offset: parent found at offset %zu (ptr=%px)\n",
                    i, cur->parent);
            break;
        }
    }

    /* cred */
    for (i = 0; i < scan_size; i += sizeof(void *)) {
        struct cred **cp = (struct cred **)(base + i);
        if (cp && *cp &&
            (unsigned long)(*cp) > 0xffff000000000000ULL &&
            i != g_offset_task_mm &&
            i != g_offset_task_parent) {
            /* Check it looks like a cred by reading uid */
            if ((*cp)->uid.val == cur->cred->uid.val) {
                g_offset_task_cred = i;
                pr_info("proc_root_auto_offset: cred found at offset %zu\n", i);
                break;
            }
        }
    }

    g_size_task_struct = scan_size;
    pr_info("proc_root_auto_offset: detected offsets: pid=%zu tgid=%zu comm=%zu mm=%zu tasks=%zu parent=%zu cred=%zu\n",
            g_offset_task_pid, g_offset_task_tgid, g_offset_task_comm,
            g_offset_task_mm, g_offset_task_tasks, g_offset_task_parent, g_offset_task_cred);

    return 0;
}

#endif
