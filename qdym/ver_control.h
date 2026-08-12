#ifndef VER_CONTROL_H
#define VER_CONTROL_H

#include <linux/version.h>

#define KERNEL_VERSION_CODE LINUX_VERSION_CODE

#define KERNEL_VER(major, minor, patch) KERNEL_VERSION(major, minor, patch)

#define IS_KERNEL_GE(major, minor, patch) \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(major, minor, patch))

#define IS_KERNEL_LT(major, minor, patch) \
    (LINUX_VERSION_CODE < KERNEL_VERSION(major, minor, patch))

#define IS_KERNEL_EQ(major, minor, patch) \
    (LINUX_VERSION_CODE == KERNEL_VERSION(major, minor, patch))

#define IS_KERNEL_RANGE(am, ap, bm, bp) \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(am, ap, 0) && \
     LINUX_VERSION_CODE <  KERNEL_VERSION(bm, bp, 0))

/* Detect CFI-enabled kernels (Android GKI 5.10+ typically) */
#define HAS_CFI IS_KERNEL_GE(5, 10, 0)

/* kallsyms_lookup_name not exported since 5.7 */
#define KALLSYMS_NOT_EXPORTED IS_KERNEL_GE(5, 7, 0)

/* for_each_process requires RCU in newer kernels */
#define FOR_EACH_PROCESS_NEEDS_RCU IS_KERNEL_GE(4, 11, 0)

#endif
