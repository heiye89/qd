#ifndef PROC_MAPS_AUTO_OFFSET_H
#define PROC_MAPS_AUTO_OFFSET_H

#include "linux_kernel_api.h"
#include "proc_root_auto_offset.h"

/* Detected offsets for struct mm_struct */
static unsigned long g_offset_mm_mmap;
static unsigned long g_offset_mm_arg_start;
static unsigned long g_offset_mm_arg_end;
static unsigned long g_offset_mm_env_start;
static unsigned long g_offset_mm_env_end;
static unsigned long g_offset_mm_start_brk;
static unsigned long g_offset_mm_brk;
static unsigned long g_offset_mm_mmap_lock;
static unsigned long g_offset_mm_rss_stat;

/* Detected offsets for struct vm_area_struct */
static unsigned long g_offset_vma_vm_start;
static unsigned long g_offset_vma_vm_end;
static unsigned long g_offset_vma_vm_flags;
static unsigned long g_offset_vma_vm_file;
static unsigned long g_offset_vma_vm_next;
static unsigned long g_offset_vma_vm_pgoff;

#define MM_MMAP(mm)        (*(struct vm_area_struct **)((unsigned char *)(mm) + g_offset_mm_mmap))
#define MM_ARG_START(mm)   (*(unsigned long *)((unsigned char *)(mm) + g_offset_mm_arg_start))
#define MM_ARG_END(mm)     (*(unsigned long *)((unsigned char *)(mm) + g_offset_mm_arg_end))
#define MM_ENV_START(mm)   (*(unsigned long *)((unsigned char *)(mm) + g_offset_mm_env_start))
#define MM_ENV_END(mm)     (*(unsigned long *)((unsigned char *)(mm) + g_offset_mm_env_end))
#define MM_START_BRK(mm)   (*(unsigned long *)((unsigned char *)(mm) + g_offset_mm_start_brk))
#define MM_BRK(mm)         (*(unsigned long *)((unsigned char *)(mm) + g_offset_mm_brk))
#define MM_MMAP_LOCK(mm)   ((struct rw_semaphore *)((unsigned char *)(mm) + g_offset_mm_mmap_lock))
#define MM_RSS_STAT(mm)    ((struct mm_rss_stat *)((unsigned char *)(mm) + g_offset_mm_rss_stat))

#define VMA_VM_START(vma)  (*(unsigned long *)((unsigned char *)(vma) + g_offset_vma_vm_start))
#define VMA_VM_END(vma)    (*(unsigned long *)((unsigned char *)(vma) + g_offset_vma_vm_end))
#define VMA_VM_FLAGS(vma)  (*(unsigned long *)((unsigned char *)(vma) + g_offset_vma_vm_flags))
#define VMA_VM_FILE(vma)   (*(struct file **)((unsigned char *)(vma) + g_offset_vma_vm_file))
#define VMA_VM_NEXT(vma)   (*(struct vm_area_struct **)((unsigned char *)(vma) + g_offset_vma_vm_next))
#define VMA_VM_PGOFF(vma)  (*(unsigned long *)((unsigned char *)(vma) + g_offset_vma_vm_pgoff))

static int __detect_mm_vma_offsets(void)
{
    struct task_struct *cur;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    unsigned char *mm_base;
    unsigned long i;
    size_t scan_size = 2048;

    cur = GET_CURRENT();
    if (!cur) return -1;

    mm = TASK_MM(cur);
    if (!mm) {
        pr_err("proc_maps_auto_offset: no mm for current\n");
        return -1;
    }

    mm_base = (unsigned char *)mm;

    /* mmap is typically the first field in mm_struct */
    vma = mm->mmap;
    for (i = 0; i < scan_size; i += sizeof(void *)) {
        struct vm_area_struct **vp = (struct vm_area_struct **)(mm_base + i);
        if (*vp == vma && vma) {
            g_offset_mm_mmap = i;
            pr_info("proc_maps_auto_offset: mmap found at offset %zu (ptr=%px)\n",
                    i, vma);
            break;
        }
    }

    /* arg_start / arg_end: scan for values matching mm_struct.arg_start */
    for (i = 0; i < scan_size; i += sizeof(unsigned long)) {
        unsigned long *lp = (unsigned long *)(mm_base + i);
        if (*lp == mm->arg_start && mm->arg_start) {
            g_offset_mm_arg_start = i;
            pr_info("proc_maps_auto_offset: arg_start found at offset %zu\n", i);
            break;
        }
    }
    for (i = 0; i < scan_size; i += sizeof(unsigned long)) {
        unsigned long *lp = (unsigned long *)(mm_base + i);
        if (*lp == mm->arg_end && mm->arg_end &&
            i != g_offset_mm_arg_start) {
            g_offset_mm_arg_end = i;
            pr_info("proc_maps_auto_offset: arg_end found at offset %zu\n", i);
            break;
        }
    }

    /* Detect vm_area_struct offsets by examining the first VMA */
    if (vma) {
        unsigned char *vma_base = (unsigned char *)vma;
        size_t vma_scan = 512;

        for (i = 0; i < vma_scan; i += sizeof(unsigned long)) {
            unsigned long *lp = (unsigned long *)(vma_base + i);
            if (*lp == vma->vm_start && vma->vm_start) {
                g_offset_vma_vm_start = i;
                pr_info("proc_maps_auto_offset: vm_start found at offset %zu\n", i);
                break;
            }
        }
        for (i = 0; i < vma_scan; i += sizeof(unsigned long)) {
            unsigned long *lp = (unsigned long *)(vma_base + i);
            if (*lp == vma->vm_end && vma->vm_end &&
                i != g_offset_vma_vm_start) {
                g_offset_vma_vm_end = i;
                pr_info("proc_maps_auto_offset: vm_end found at offset %zu\n", i);
                break;
            }
        }
        for (i = 0; i < vma_scan; i += sizeof(unsigned long)) {
            unsigned long *lp = (unsigned long *)(vma_base + i);
            if (*lp == vma->vm_flags &&
                i != g_offset_vma_vm_start &&
                i != g_offset_vma_vm_end) {
                g_offset_vma_vm_flags = i;
                pr_info("proc_maps_auto_offset: vm_flags found at offset %zu\n", i);
                break;
            }
        }
        for (i = 0; i < vma_scan; i += sizeof(void *)) {
            struct file **fp = (struct file **)(vma_base + i);
            if (*fp == vma->vm_file) {
                g_offset_vma_vm_file = i;
                pr_info("proc_maps_auto_offset: vm_file found at offset %zu\n", i);
                break;
            }
        }
        for (i = 0; i < vma_scan; i += sizeof(void *)) {
            struct vm_area_struct **vp = (struct vm_area_struct **)(vma_base + i);
            if (*vp == vma->vm_next) {
                g_offset_vma_vm_next = i;
                pr_info("proc_maps_auto_offset: vm_next found at offset %zu\n", i);
                break;
            }
        }
    }

    pr_info("proc_maps_auto_offset: detection complete\n");
    return 0;
}

#endif
