// SPDX-License-Identifier: GPL-2.0
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/string.h>

#if !defined(CONFIG_ARM64)
#error "defex_lsposed_compat is intended for arm64 only"
#endif

#define DRIVER_NAME "defex_lsposed_compat"

static bool bypass;
module_param(bypass, bool, 0644);
MODULE_PARM_DESC(bypass, "Enable the narrow LSPosed DEFEX bypass after dry-run validation");

static bool qstr_eq(const struct qstr *q, const char *s)
{
    size_t len;

    if (!q || !q->name || !s)
        return false;

    len = strlen(s);
    return q->len == len && !memcmp(q->name, s, len);
}

/*
 * /data is a mount point, so f_path.dentry ancestry starts at the filesystem
 * root beneath /data. Match only the exact LSPosed module tail:
 *   adb/modules/zygisk_lsposed/zygisk/arm64-v8a.so
 */
static bool is_lsposed_zygisk_so(const struct file *file)
{
    struct dentry *d;

    if (!file)
        return false;

    d = file->f_path.dentry;
    if (!d || !qstr_eq(&d->d_name, "arm64-v8a.so"))
        return false;

    d = d->d_parent;
    if (!d || !qstr_eq(&d->d_name, "zygisk"))
        return false;

    d = d->d_parent;
    if (!d || !qstr_eq(&d->d_name, "zygisk_lsposed"))
        return false;

    d = d->d_parent;
    if (!d || !qstr_eq(&d->d_name, "modules"))
        return false;

    d = d->d_parent;
    if (!d || !qstr_eq(&d->d_name, "adb"))
        return false;

    return true;
}

static bool is_system_app_process64(const struct task_struct *task)
{
    const struct file *exe;
    struct dentry *d;

    if (!task || !task->mm)
        return false;

    exe = READ_ONCE(task->mm->exe_file);
    if (!exe)
        return false;

    d = exe->f_path.dentry;
    if (!d || !qstr_eq(&d->d_name, "app_process64"))
        return false;

    d = d->d_parent;
    return d && qstr_eq(&d->d_name, "bin");
}

static int defex_lsposed_pre_handler(struct kprobe *probe, struct pt_regs *regs)
{
    struct task_struct *task = (struct task_struct *)regs->regs[0];
    struct file *file = (struct file *)regs->regs[1];

    (void)probe;

    if (task != current)
        return 0;

    if (!uid_eq(current_euid(), GLOBAL_ROOT_UID))
        return 0;

    if (!is_system_app_process64(current) || !is_lsposed_zygisk_so(file))
        return 0;

    pr_info_ratelimited(DRIVER_NAME ": matched pid=%d comm=%s bypass=%d\n",
                        task_pid_nr(current), current->comm, bypass ? 1 : 0);

    /*
     * KernelSU's Samsung compatibility layer already uses this exact technique
     * for KSU-domain tasks: replace the task argument with NULL before
     * task_defex_enforce() evaluates it. Keep this helper restricted to the
     * exact app_process64 + LSPosed Zygisk library match above.
     */
    if (READ_ONCE(bypass))
        regs->regs[0] = 0;

    return 0;
}

static struct kprobe defex_enforce_kprobe = {
    .symbol_name = "task_defex_enforce",
    .pre_handler = defex_lsposed_pre_handler,
};

static int __init defex_lsposed_init(void)
{
    int ret;

    ret = register_kprobe(&defex_enforce_kprobe);
    if (ret) {
        pr_err(DRIVER_NAME ": register_kprobe(task_defex_enforce) failed: %d\n", ret);
        return ret;
    }

    pr_info(DRIVER_NAME ": loaded in dry-run mode; set bypass=1 only after match validation\n");
    return 0;
}

static void __exit defex_lsposed_exit(void)
{
    unregister_kprobe(&defex_enforce_kprobe);
    pr_info(DRIVER_NAME ": unloaded\n");
}

module_init(defex_lsposed_init);
module_exit(defex_lsposed_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Root My Galaxy");
MODULE_DESCRIPTION("Narrow Samsung DEFEX compatibility test for LSPosed on SM-S938B ZZI4");
