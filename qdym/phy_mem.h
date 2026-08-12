#ifndef PHY_MEM_H
#define PHY_MEM_H

#include "linux_kernel_api.h"
#include "phy_mem_auto_offset.h"

#define PHY_MEM_MAX_SIZE (2 * 1024 * 1024)

struct phy_mem_args {
    unsigned long addr;       /* physical address */
    void __user *buf;
    size_t size;
    size_t bytes_copied;
};

static int phy_mem_read(struct phy_mem_args __user *uargs)
{
    struct phy_mem_args args;
    void *kbuf;
    void __iomem *map;
    unsigned long pa;
    size_t size;

    if (copy_from_user(&args, uargs, sizeof(args)))
        return -EFAULT;

    if (args.size == 0 || args.size > PHY_MEM_MAX_SIZE)
        return -EINVAL;

    size = args.size;
    pa = args.addr;

    kbuf = kmalloc(size, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    map = IOREMAP(pa, size);
    if (!map || IS_ERR(map)) {
        pr_err("phy_mem: ioremap(%lx, %zu) failed\n", pa, size);
        kfree(kbuf);
        return -EIO;
    }

    memcpy_fromio(kbuf, map, size);
    IOUNMAP(map);

    args.bytes_copied = size;

    if (copy_to_user(args.buf, kbuf, size)) {
        kfree(kbuf);
        return -EFAULT;
    }
    if (copy_to_user(&uargs->bytes_copied, &args.bytes_copied,
                     sizeof(args.bytes_copied))) {
        kfree(kbuf);
        return -EFAULT;
    }

    kfree(kbuf);
    return 0;
}

static int phy_mem_write(struct phy_mem_args __user *uargs)
{
    struct phy_mem_args args;
    void *kbuf;
    void __iomem *map;
    unsigned long pa;
    size_t size;

    if (copy_from_user(&args, uargs, sizeof(args)))
        return -EFAULT;

    if (args.size == 0 || args.size > PHY_MEM_MAX_SIZE)
        return -EINVAL;

    size = args.size;
    pa = args.addr;

    kbuf = kmalloc(size, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    if (copy_from_user(kbuf, args.buf, size)) {
        kfree(kbuf);
        return -EFAULT;
    }

    map = IOREMAP(pa, size);
    if (!map || IS_ERR(map)) {
        pr_err("phy_mem: ioremap(%lx, %zu) failed\n", pa, size);
        kfree(kbuf);
        return -EIO;
    }

    memcpy_toio(map, kbuf, size);
    IOUNMAP(map);

    args.bytes_copied = size;

    if (copy_to_user(&uargs->bytes_copied, &args.bytes_copied,
                     sizeof(args.bytes_copied))) {
        kfree(kbuf);
        return -EFAULT;
    }

    kfree(kbuf);
    return 0;
}

#endif
