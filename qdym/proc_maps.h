#ifndef PROC_MAPS_H
#define PROC_MAPS_H

#include "linux_kernel_api.h"
#include "proc_root_auto_offset.h"
#include "proc_maps_auto_offset.h"
#include "hide_procfs_dir.h"

#define PROC_MAPS_MAX_ENTRIES 512

struct proc_maps_entry {
    unsigned long vm_start;
    unsigned long vm_end;
    unsigned long vm_flags;
    unsigned long vm_pgoff;
    char path[256];
};

struct proc_maps_args {
    int pid;
    struct proc_maps_entry __user *buf;
    int max_count;
    int actual_count;
};

static int proc_maps_get(struct proc_maps_args __user *uargs)
{
    struct proc_maps_args args;
    struct proc_maps_entry *kbuf = NULL;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    int count = 0;
    int ret = 0;

    if (copy_from_user(&args, uargs, sizeof(args)))
        return -EFAULT;

    if (args.max_count <= 0 || args.max_count > PROC_MAPS_MAX_ENTRIES)
        return -EINVAL;

    kbuf = kmalloc_array(args.max_count, sizeof(*kbuf), GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    task = FIND_TASK_BY_VPID(args.pid);
    if (!task) {
        kfree(kbuf);
        return -ESRCH;
    }

    mm = GET_TASK_MM(task);
    if (!mm) {
        kfree(kbuf);
        return -EINVAL;
    }

    vma = MM_MMAP(mm);
    while (vma && count < args.max_count) {
        struct file *file;

        kbuf[count].vm_start = VMA_VM_START(vma);
        kbuf[count].vm_end   = VMA_VM_END(vma);
        kbuf[count].vm_flags = VMA_VM_FLAGS(vma);
        kbuf[count].vm_pgoff = VMA_VM_PGOFF(vma);

        file = VMA_VM_FILE(vma);
        if (file) {
            char *p = d_path(&file->f_path, kbuf[count].path,
                             sizeof(kbuf[count].path));
            if (IS_ERR(p))
                kbuf[count].path[0] = '\0';
            else
                strncpy(kbuf[count].path, p, sizeof(kbuf[count].path) - 1);
        } else {
            kbuf[count].path[0] = '\0';
        }

        count++;
        vma = VMA_VM_NEXT(vma);
    }

    MMPUT(mm);

    args.actual_count = count;

    if (count > 0) {
        if (copy_to_user(args.buf, kbuf, count * sizeof(*kbuf))) {
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
