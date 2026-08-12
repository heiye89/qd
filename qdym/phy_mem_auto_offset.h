#ifndef PHY_MEM_AUTO_OFFSET_H
#define PHY_MEM_AUTO_OFFSET_H

#include "linux_kernel_api.h"

/* PAGE_OFFSET: kernel virtual base address. Varies by architecture and config.
 * ARM64 typically: 0xffffff8000000000, 0xffffffe000000000, etc.
 * We detect by checking ioremap / phys_to_virt results.
 */
static unsigned long g_page_offset;
static unsigned long g_phys_offset;
static unsigned long g_kimage_voffset;

#define PAGE_OFFSET_VAL  g_page_offset
#define PHYS_OFFSET_VAL  g_phys_offset

static int __detect_phy_mem_offsets(void)
{
    unsigned long test_pa = 0x40000000; /* A common low physical address */
    void *va;

    /* Try to map a page and compute PAGE_OFFSET */
    va = IOREMAP(test_pa, PAGE_SIZE);
    if (va && !IS_ERR(va)) {
        g_page_offset = (unsigned long)va - test_pa;
        pr_info("phy_mem_auto_offset: PAGE_OFFSET=%lx\n", g_page_offset);
        IOUNMAP(va);
    } else {
        /* Fallback: use known ARM64 offset */
        g_page_offset = 0xffffff8000000000ULL;
        pr_info("phy_mem_auto_offset: using default PAGE_OFFSET=%lx\n", g_page_offset);
    }

    /* Try to detect kimage_voffset from /proc/kallsyms */
    /* In modern ARM64 kernels: kimage_voffset is a kernel symbol */
    {
        unsigned long kimage_addr;
        kimage_addr = lkapi_kallsyms_lookup_name("kimage_voffset");
        if (kimage_addr) {
            g_kimage_voffset = *(unsigned long *)kimage_addr;
            pr_info("phy_mem_auto_offset: kimage_voffset=%lx\n", g_kimage_voffset);
        } else {
            g_kimage_voffset = 0;
        }
    }

    return 0;
}

#endif
