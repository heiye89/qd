#ifndef LINUX_KERNEL_API_H
#define LINUX_KERNEL_API_H

#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/string.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/unistd.h>
#include <linux/dirent.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/fdtable.h>
#include <linux/io.h>
#include <linux/err.h>

/* ===== kallsyms_lookup_name (5.7+ kprobe fallback) ===== */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)

static unsigned long (*t_kallsyms_lookup_name)(const char *name);

static int __lkapi_kprobe_handler(struct kprobe *p, struct pt_regs *regs)
{
    return 0;
}

static unsigned long __lkapi_get_kallsyms_func(void)
{
    struct kprobe probe;
    unsigned long addr;

    memset(&probe, 0, sizeof(probe));
    probe.pre_handler = __lkapi_kprobe_handler;
    probe.symbol_name = "kallsyms_lookup_name";
    if (register_kprobe(&probe))
        return 0;
    addr = (unsigned long)probe.addr;
    unregister_kprobe(&probe);
    return addr;
}

static inline unsigned long lkapi_kallsyms_lookup_name(const char *name)
{
    if (!t_kallsyms_lookup_name) {
        t_kallsyms_lookup_name = (void *)__lkapi_get_kallsyms_func();
        if (!t_kallsyms_lookup_name)
            return 0;
    }
    return t_kallsyms_lookup_name(name);
}

#else

static inline unsigned long lkapi_kallsyms_lookup_name(const char *name)
{
    return kallsyms_lookup_name(name);
}

#endif

/* ===== Function Pointer Types ===== */

typedef struct file *(*fp_filp_open)(const char *, int, umode_t);
typedef int (*fp_filp_close)(struct file *, fl_owner_t);
typedef ssize_t (*fp_kernel_read)(struct file *, void *, size_t, loff_t *);
typedef ssize_t (*fp_kernel_write)(struct file *, const void *, size_t, loff_t *);
typedef struct task_struct *(*fp_find_task_by_vpid)(pid_t);
typedef struct task_struct *(*fp_get_current)(void);
typedef struct mm_struct *(*fp_get_task_mm)(struct task_struct *);
typedef void (*fp_mmput)(struct mm_struct *);
typedef int (*fp_access_remote_vm)(struct mm_struct *, unsigned long, void *, int, unsigned int);
typedef int (*fp_access_process_vm)(struct task_struct *, unsigned long, void *, int, unsigned int);
typedef unsigned long (*fp_virt_to_phys)(volatile void *);
typedef void *(*fp_phys_to_virt)(unsigned long);
typedef void *(*fp_ioremap)(unsigned long, unsigned long);
typedef void (*fp_iounmap)(volatile void __iomem *);
typedef pte_t *(*fp_pte_offset_map)(pmd_t *, unsigned long);
typedef unsigned long (*fp_pte_val)(pte_t);

/* ===== CFI Bypass Wrappers ===== */

__attribute__((no_sanitize("cfi")))
static inline struct file *lkapi_filp_open(const char *name, int flags, umode_t mode,
                                            fp_filp_open p)
{ return p(name, flags, mode); }

__attribute__((no_sanitize("cfi")))
static inline int lkapi_filp_close(struct file *f, fl_owner_t id, fp_filp_close p)
{ return p(f, id); }

__attribute__((no_sanitize("cfi")))
static inline ssize_t lkapi_kernel_read(struct file *f, void *buf, size_t n, loff_t *pos,
                                         fp_kernel_read p)
{ return p(f, buf, n, pos); }

__attribute__((no_sanitize("cfi")))
static inline ssize_t lkapi_kernel_write(struct file *f, const void *buf, size_t n, loff_t *pos,
                                          fp_kernel_write p)
{ return p(f, buf, n, pos); }

__attribute__((no_sanitize("cfi")))
static inline struct task_struct *lkapi_find_task_by_vpid(pid_t vnr, fp_find_task_by_vpid p)
{ return p(vnr); }

__attribute__((no_sanitize("cfi")))
static inline struct task_struct *lkapi_get_current(fp_get_current p)
{ return p(); }

__attribute__((no_sanitize("cfi")))
static inline struct mm_struct *lkapi_get_task_mm(struct task_struct *t, fp_get_task_mm p)
{ return p(t); }

__attribute__((no_sanitize("cfi")))
static inline void lkapi_mmput(struct mm_struct *m, fp_mmput p)
{ p(m); }

__attribute__((no_sanitize("cfi")))
static inline int lkapi_access_remote_vm(struct mm_struct *mm, unsigned long addr,
                                          void *buf, int len, unsigned int gup,
                                          fp_access_remote_vm p)
{ return p(mm, addr, buf, len, gup); }

__attribute__((no_sanitize("cfi")))
static inline int lkapi_access_process_vm(struct task_struct *t, unsigned long addr,
                                           void *buf, int len, unsigned int gup,
                                           fp_access_process_vm p)
{ return p(t, addr, buf, len, gup); }

__attribute__((no_sanitize("cfi")))
static inline unsigned long lkapi_virt_to_phys(volatile void *va, fp_virt_to_phys p)
{ return p(va); }

__attribute__((no_sanitize("cfi")))
static inline void *lkapi_phys_to_virt(unsigned long pa, fp_phys_to_virt p)
{ return p(pa); }

__attribute__((no_sanitize("cfi")))
static inline void *lkapi_ioremap(unsigned long pa, unsigned long sz, fp_ioremap p)
{ return p(pa, sz); }

__attribute__((no_sanitize("cfi")))
static inline void lkapi_iounmap(volatile void __iomem *addr, fp_iounmap p)
{ p(addr); }

/* ===== Resolution Helper ===== */

#define LKAPI_RESOLVE(name)                                                    \
    do {                                                                       \
        unsigned long __addr = lkapi_kallsyms_lookup_name(#name);              \
        if (!__addr) {                                                         \
            pr_err("lkapi: failed to resolve %s\n", #name);                    \
            return -ENXIO;                                                     \
        }                                                                      \
        _p_##name = (void *)__addr;                                            \
        pr_info("lkapi: %s @ 0x%px\n", #name, (void *)__addr);                \
    } while (0)

/* ===== Global Function Pointer Instances ===== */
/* These must be defined exactly once (in rwProcMem_module.c).
 * All other .h files use: extern fp_xxx _p_xxx;
 */

#define LKAPI_DECLARE(name, type) extern type _p_##name;

LKAPI_DECLARE(filp_open,         fp_filp_open);
LKAPI_DECLARE(filp_close,        fp_filp_close);
LKAPI_DECLARE(kernel_read,       fp_kernel_read);
LKAPI_DECLARE(kernel_write,      fp_kernel_write);
LKAPI_DECLARE(find_task_by_vpid, fp_find_task_by_vpid);
LKAPI_DECLARE(get_task_mm,       fp_get_task_mm);
LKAPI_DECLARE(mmput,             fp_mmput);
LKAPI_DECLARE(access_remote_vm,  fp_access_remote_vm);
LKAPI_DECLARE(access_process_vm, fp_access_process_vm);
LKAPI_DECLARE(virt_to_phys,      fp_virt_to_phys);
LKAPI_DECLARE(phys_to_virt,      fp_phys_to_virt);
LKAPI_DECLARE(ioremap,           fp_ioremap);
LKAPI_DECLARE(iounmap,           fp_iounmap);

#undef LKAPI_DECLARE

/* ===== Convenience macros for calling via wrappers ===== */

#define FILP_OPEN(name, flags, mode)                                           \
    lkapi_filp_open((name), (flags), (mode), _p_filp_open)
#define FILP_CLOSE(f, id)                                                      \
    lkapi_filp_close((f), (id), _p_filp_close)
#define KERNEL_READ(f, buf, n, pos)                                            \
    lkapi_kernel_read((f), (buf), (n), (pos), _p_kernel_read)
#define KERNEL_WRITE(f, buf, n, pos)                                           \
    lkapi_kernel_write((f), (buf), (n), (pos), _p_kernel_write)
#define FIND_TASK_BY_VPID(vnr)                                                 \
    lkapi_find_task_by_vpid((vnr), _p_find_task_by_vpid)
#define GET_CURRENT()                                                          \
    (current)
#define GET_TASK_MM(t)                                                         \
    lkapi_get_task_mm((t), _p_get_task_mm)
#define MMPUT(m)                                                               \
    lkapi_mmput((m), _p_mmput)
#define ACCESS_REMOTE_VM(mm, addr, buf, len, gup)                              \
    lkapi_access_remote_vm((mm), (addr), (buf), (len), (gup), _p_access_remote_vm)
#define ACCESS_PROCESS_VM(t, addr, buf, len, gup)                              \
    lkapi_access_process_vm((t), (addr), (buf), (len), (gup), _p_access_process_vm)
#define VIRT_TO_PHYS(va)                                                       \
    lkapi_virt_to_phys((va), _p_virt_to_phys)
#define PHYS_TO_VIRT(pa)                                                       \
    lkapi_phys_to_virt((pa), _p_phys_to_virt)
#define IOREMAP(pa, sz)                                                        \
    lkapi_ioremap((pa), (sz), _p_ioremap)
#define IOUNMAP(addr)                                                          \
    lkapi_iounmap((addr), _p_iounmap)

#endif
