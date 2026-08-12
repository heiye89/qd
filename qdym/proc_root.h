#ifndef PROC_ROOT_H
#define PROC_ROOT_H

#include "linux_kernel_api.h"
#include "proc_root_auto_offset.h"

static int proc_root_get_pid_count(void)
{
    struct task_struct *task;
    int count = 0;

    rcu_read_lock();
    for_each_process(task) {
        count++;
    }
    rcu_read_unlock();

    return count;
}

static int proc_root_get_uid(int pid)
{
    struct task_struct *task;
    int uid = -1;

    task = FIND_TASK_BY_VPID(pid);
    if (task && TASK_CRED(task)) {
        uid = (int)(TASK_CRED(task)->uid.val);
    }
    return uid;
}

static const char *proc_root_get_comm(int pid)
{
    struct task_struct *task;

    task = FIND_TASK_BY_VPID(pid);
    if (task)
        return TASK_COMM(task);
    return NULL;
}

#endif
