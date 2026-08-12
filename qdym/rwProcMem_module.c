#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/capability.h>

#include "linux_kernel_api.h"
#include "ver_control.h"
#include "proc_root_auto_offset.h"
#include "proc_list_auto_offset.h"
#include "proc_maps_auto_offset.h"
#include "phy_mem_auto_offset.h"
#include "proc_cmdline_auto_offset.h"
#include "hide_procfs_dir.h"
#include "proc_root.h"
#include "proc_list.h"
#include "proc_maps.h"
#include "proc_rss.h"
#include "proc_cmdline.h"
#include "phy_mem.h"
#include "rwProcMem_module.h"

/* ---- virtual memory read ---- */
static int do_read_vm(struct vm_mem_args __user *uargs)
{
    struct vm_mem_args args;
    struct task_struct *task;
    struct mm_struct *mm;
    void *kbuf = NULL;
    int len;

    if (copy_from_user(&args, uargs, sizeof(args)))
        return -EFAULT;
    if (args.size == 0 || args.size > QDYM_VM_MAX_SIZE)
        return -EINVAL;
    if (args.pid <= 0)
        return -EINVAL;

    kbuf = kmalloc(args.size, GFP_KERNEL);
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

    len = ACCESS_REMOTE_VM(mm, args.addr, kbuf, args.size, 0);
    MMPUT(mm);

    if (len < 0) {
        kfree(kbuf);
        return len;
    }
    args.bytes_copied = len;

    if (len > 0) {
        if (copy_to_user(args.buf, kbuf, len)) {
            kfree(kbuf);
            return -EFAULT;
        }
    }
    if (copy_to_user(&uargs->bytes_copied, &args.bytes_copied,
                     sizeof(args.bytes_copied))) {
        kfree(kbuf);
        return -EFAULT;
    }

    kfree(kbuf);
    return 0;
}

/* ---- virtual memory write ---- */
static int do_write_vm(struct vm_mem_args __user *uargs)
{
    struct vm_mem_args args;
    struct task_struct *task;
    struct mm_struct *mm;
    void *kbuf = NULL;
    int len;

    if (copy_from_user(&args, uargs, sizeof(args)))
        return -EFAULT;
    if (args.size == 0 || args.size > QDYM_VM_MAX_SIZE)
        return -EINVAL;
    if (args.pid <= 0)
        return -EINVAL;

    kbuf = kmalloc(args.size, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    if (copy_from_user(kbuf, args.buf, args.size)) {
        kfree(kbuf);
        return -EFAULT;
    }

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

    len = ACCESS_REMOTE_VM(mm, args.addr, kbuf, args.size,
                            FOLL_FORCE | FOLL_WRITE);
    MMPUT(mm);

    if (len < 0) {
        kfree(kbuf);
        return len;
    }
    args.bytes_copied = len;

    if (copy_to_user(&uargs->bytes_copied, &args.bytes_copied,
                     sizeof(args.bytes_copied))) {
        kfree(kbuf);
        return -EFAULT;
    }

    kfree(kbuf);
    return 0;
}

/* ---- ioctl dispatcher ---- */
static long qdym_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    if (_IOC_TYPE(cmd) != QDYM_IOC_MAGIC)
        return -ENOTTY;

    if (!uid_eq(current_uid(), GLOBAL_ROOT_UID) && !capable(CAP_SYS_ADMIN)) {
        pr_warn("qdym: permission denied uid=%u\n", __kuid_val(current_uid()));
        return -EPERM;
    }

    switch (cmd) {
    case QDYM_IOC_GET_PROC_LIST:
        return proc_list_get((struct proc_list_args __user *)arg);
    case QDYM_IOC_HIDE_PID:
        {
            int pid = (int)arg;
            if (pid <= 1) return -EINVAL;
            if (add_hidden_pid(pid)) return -ENOSPC;
            hide_procfs_pid(pid);
            pr_info("qdym: hid PID %d\n", pid);
            return 0;
        }
    case QDYM_IOC_UNHIDE_PID:
        {
            int pid = (int)arg;
            int ret = remove_hidden_pid(pid);
            if (ret) return ret;
            unhide_procfs_pid(pid);
            pr_info("qdym: unhid PID %d\n", pid);
            return 0;
        }
    case QDYM_IOC_READ_VM:
        return do_read_vm((struct vm_mem_args __user *)arg);
    case QDYM_IOC_WRITE_VM:
        return do_write_vm((struct vm_mem_args __user *)arg);
    case QDYM_IOC_GET_MAPS:
        return proc_maps_get((struct proc_maps_args __user *)arg);
    case QDYM_IOC_GET_RSS:
        return proc_rss_get((struct proc_rss_args __user *)arg);
    case QDYM_IOC_GET_CMDLINE:
        return proc_cmdline_get((struct proc_cmdline_args __user *)arg);
    case QDYM_IOC_READ_PHY_MEM:
        return phy_mem_read((struct phy_mem_args __user *)arg);
    case QDYM_IOC_WRITE_PHY_MEM:
        return phy_mem_write((struct phy_mem_args __user *)arg);
    default:
        return -ENOTTY;
    }
}

static const struct file_operations qdym_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = qdym_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl   = qdym_ioctl,
#endif
};

static struct miscdevice qdym_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &qdym_fops,
    .mode  = 0600,
};

/* ---- init ---- */
static int __init qdym_init(void)
{
    int ret;

    /* 1. Resolve kernel symbols */
    LKAPI_RESOLVE(filp_open);
    LKAPI_RESOLVE(filp_close);
    LKAPI_RESOLVE(kernel_read);
    LKAPI_RESOLVE(kernel_write);
    LKAPI_RESOLVE(find_task_by_vpid);
    LKAPI_RESOLVE(get_task_mm);
    LKAPI_RESOLVE(mmput);
    LKAPI_RESOLVE(access_remote_vm);
    LKAPI_RESOLVE(access_process_vm);
    LKAPI_RESOLVE(virt_to_phys);
    LKAPI_RESOLVE(phys_to_virt);
    LKAPI_RESOLVE(ioremap);
    LKAPI_RESOLVE(iounmap);

    pr_info("qdym: all kernel symbols resolved\n");

    /* 2. Detect struct offsets at runtime */
    __detect_task_offsets();
    __detect_proc_list_offsets();
    __detect_mm_vma_offsets();
    __detect_phy_mem_offsets();
    __detect_cmdline_offsets();

    pr_info("qdym: all offsets detected\n");

    /* 3. Init hidden pids */
    g_hidden_count = 0;
    mutex_init(&g_hidden_lock);

    /* 4. Register device */
    ret = misc_register(&qdym_dev);
    if (ret) {
        pr_err("qdym: misc_register failed: %d\n", ret);
        return ret;
    }

    pr_info("qdym: loaded. device=/dev/%s version=%s\n",
            DEVICE_NAME,
            IS_KERNEL_GE(5,10,0) ? "5.10+" : "pre-5.10");
    return 0;
}

/* ---- exit ---- */
static void __exit qdym_exit(void)
{
    unhide_all_pids();
    misc_deregister(&qdym_dev);
    pr_info("qdym: unloaded.\n");
}

module_init(qdym_init);
module_exit(qdym_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("systemnb");
MODULE_DESCRIPTION("Android kernel driver: proc list/hide, virt/phys mem r/w, maps, rss, cmdline");
