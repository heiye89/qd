#ifndef PROC_RSS_H
#define PROC_RSS_H

#include "linux_kernel_api.h"
#include "proc_root_auto_offset.h"
#include "proc_maps_auto_offset.h"

struct proc_rss_info {
    unsigned long rss;
    unsigned long vss;
    unsigned long pss;
    unsigned long shared_clean;
    unsigned long shared_dirty;
    unsigned long private_clean;
    unsigned long private_dirty;
};

struct proc_rss_args {
    int pid;
    struct proc_rss_info info;
};

static int proc_rss_get(struct proc_rss_args __user *uargs)
{
    struct proc_rss_args args;
    struct proc_rss_info info;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    unsigned long rss_pages = 0;
    unsigned long vss_pages = 0;

    if (copy_from_user(&args, uargs, sizeof(args)))
        return -EFAULT;

    task = FIND_TASK_BY_VPID(args.pid);
    if (!task)
        return -ESRCH;

    mm = GET_TASK_MM(task);
    if (!mm)
        return -EINVAL;

    rss_pages = get_mm_rss(mm);

    QDYM_VMA_ITERATOR(vmi, mm);
    QDYM_FOR_EACH_VMA(vmi, vma) {
        unsigned long size = VMA_VM_END(vma) - VMA_VM_START(vma);
        vss_pages += size / PAGE_SIZE;
    }

    MMPUT(mm);

    memset(&info, 0, sizeof(info));
    info.rss = rss_pages * PAGE_SIZE;
    info.vss = vss_pages * PAGE_SIZE;
    info.pss = info.rss;

    args.info = info;

    if (copy_to_user(&uargs->info, &args.info, sizeof(args.info)))
        return -EFAULT;

    return 0;
}

#endif
