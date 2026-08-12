#ifndef RWPROCMEM_MODULE_H
#define RWPROCMEM_MODULE_H

#include <linux/ioctl.h>

#define DEVICE_NAME "qdym"

/* IOCTL magic */
#define QDYM_IOC_MAGIC 'Q'

/* Process list */
#define QDYM_IOC_GET_PROC_LIST  _IOWR(QDYM_IOC_MAGIC, 1, struct proc_list_args)

/* Process hiding */
#define QDYM_IOC_HIDE_PID        _IOW(QDYM_IOC_MAGIC, 2, int)
#define QDYM_IOC_UNHIDE_PID      _IOW(QDYM_IOC_MAGIC, 3, int)

/* Virtual memory read/write */
#define QDYM_IOC_READ_VM         _IOWR(QDYM_IOC_MAGIC, 4, struct vm_mem_args)
#define QDYM_IOC_WRITE_VM        _IOWR(QDYM_IOC_MAGIC, 5, struct vm_mem_args)

/* Process maps */
#define QDYM_IOC_GET_MAPS        _IOWR(QDYM_IOC_MAGIC, 6, struct proc_maps_args)

/* Process RSS */
#define QDYM_IOC_GET_RSS         _IOWR(QDYM_IOC_MAGIC, 7, struct proc_rss_args)

/* Kernel cmdline */
#define QDYM_IOC_GET_CMDLINE     _IOWR(QDYM_IOC_MAGIC, 8, struct proc_cmdline_args)

/* Physical memory read/write */
#define QDYM_IOC_READ_PHY_MEM    _IOWR(QDYM_IOC_MAGIC, 9, struct phy_mem_args)
#define QDYM_IOC_WRITE_PHY_MEM   _IOWR(QDYM_IOC_MAGIC, 10, struct phy_mem_args)

#define QDYM_VM_MAX_SIZE (2 * 1024 * 1024)

struct vm_mem_args {
    int pid;
    unsigned long addr;
    void __user *buf;
    size_t size;
    size_t bytes_copied;
};

/* Function pointer definitions (defined once in rwProcMem_module.c) */
#define LKAPI_DEFINE(name, type) type _p_##name;

LKAPI_DEFINE(filp_open,         fp_filp_open);
LKAPI_DEFINE(filp_close,        fp_filp_close);
LKAPI_DEFINE(kernel_read,       fp_kernel_read);
LKAPI_DEFINE(kernel_write,      fp_kernel_write);
LKAPI_DEFINE(find_task_by_vpid, fp_find_task_by_vpid);
LKAPI_DEFINE(get_task_mm,       fp_get_task_mm);
LKAPI_DEFINE(mmput,             fp_mmput);
LKAPI_DEFINE(access_remote_vm,  fp_access_remote_vm);
LKAPI_DEFINE(access_process_vm, fp_access_process_vm);
LKAPI_DEFINE(virt_to_phys,      fp_virt_to_phys);
LKAPI_DEFINE(phys_to_virt,      fp_phys_to_virt);
LKAPI_DEFINE(ioremap,           fp_ioremap);
LKAPI_DEFINE(iounmap,           fp_iounmap);

#undef LKAPI_DEFINE

#endif
