#ifndef PROC_LIST_H
#define PROC_LIST_H

#include "linux_kernel_api.h"
#include "proc_root_auto_offset.h"
#include "proc_list_auto_offset.h"
#include "hide_procfs_dir.h"

#define PROC_LIST_MAX_ENTRIES 4096

struct proc_list_entry {
    int pid;
    int tgid;
    int ppid;
    char comm[TASK_COMM_LEN];
    unsigned long long start_time;
    long state;
    unsigned int flags;
    int prio;
};

struct proc_list_args {
    struct proc_list_entry __user *buf;
    int max_count;
    int actual_count;
};

static int proc_list_get(struct proc_list_args __user *uargs)
{
    struct proc_list_args args;
    struct proc_list_entry *kbuf = NULL;
    struct task_struct *task;
    int count = 0;
    int ret = 0;

    if (copy_from_user(&args, uargs, sizeof(args)))
        return -EFAULT;

    if (args.max_count <= 0 || args.max_count > PROC_LIST_MAX_ENTRIES)
        return -EINVAL;

    kbuf = kmalloc_array(args.max_count, sizeof(*kbuf), GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    rcu_read_lock();
    for_each_process(task) {
        if (count >= args.max_count)
            break;

        if (is_pid_hidden(TASK_PID(task)))
            continue;

        kbuf[count].pid        = TASK_PID(task);
        kbuf[count].tgid       = TASK_TGID(task);
        kbuf[count].ppid       = TASK_PARENT(task) ? TASK_PID(TASK_PARENT(task)) : 0;
        memcpy(kbuf[count].comm, TASK_COMM(task), TASK_COMM_LEN);
        kbuf[count].comm[TASK_COMM_LEN - 1] = '\0';
        kbuf[count].state      = TASK_STATE(task);
        kbuf[count].flags      = TASK_FLAGS(task);
        kbuf[count].prio       = TASK_PRIO(task);
        count++;
    }
    rcu_read_unlock();

    args.actual_count = count;

    if (count > 0) {
        if (copy_to_user(uargs->buf, kbuf, count * sizeof(*kbuf))) {
            ret = -EFAULT;
            goto out;
        }
    }
    if (copy_to_user(&uargs->actual_count, &args.actual_count,
                     sizeof(args.actual_count)))
        ret = -EFAULT;

out:
    kfree(kbuf);
    return ret;
}

#endif
