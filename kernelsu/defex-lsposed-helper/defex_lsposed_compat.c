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

static bool file_basename_is(const struct file *file, const char *name)
{
    return file && file->f_path.dentry && qstr_eq(&file->f_path.dentry->d_name, name);
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

static void log_candidate(const struct task_struct *task, const struct file *file,
                          bool same_task, bool root_euid, bool app_process,
                          bool lsposed_file)
{
    const char *file_name = "<null>";
    const char *p1 = "<null>";
    const char *p2 = "<null>";
    struct dentry *d;

    if (file && file->f_path.dentry) {
        d = file->f_path.dentry;
        if (d->d_name.name)
            file_name = d->d_name.name;
        d = d->d_parent;
        if (d && d->d_name.name)
            p1 = d->d_name.name;
        if (d)
            d = d->d_parent;
        if (d && d->d_name.name)
            p2 = d->d_name.name;
    }

    pr_info_ratelimited(
        DRIVER_NAME ": candidate cur=%s/%d task=%s/%d uid=%u euid=%u same=%d app64=%d lspfile=%d file=%s p1=%s p2=%s bypass=%d\n",
        current->comm, task_pid_nr(current), task ? task->comm : "<null>",
        task ? task_pid_nr(task) : -1, __kuid_val(current_uid()),
        __kuid_val(current_euid()), same_task ? 1 : 0, app_process ? 1 : 0,
        lsposed_file ? 1 : 0, file_name, p1, p2, bypass ? 1 : 0);
}

static int defex_lsposed_pre_handler(struct kprobe *probe, struct pt_regs *regs)
{
    struct task_struct *task = (struct task_struct *)regs->regs[0];
    struct file *file = (struct file *)regs->regs[1];
    bool same_task;
    bool root_euid;
    bool app_process;
    bool lsposed_file;

    (void)probe;

    same_task = task == current;
    root_euid = uid_eq(current_euid(), GLOBAL_ROOT_UID);
    app_process = is_system_app_process64(current);
    lsposed_file = is_lsposed_zygisk_so(file);

    /*
     * Dry-run diagnostic: log any task_defex_enforce() call whose target file
     * has the same basename as the LSPosed Zygisk library. This deliberately
     * happens before the restrictive bypass predicates so we can identify
     * which predicate differs on Samsung's ch_zygote path without weakening
     * enforcement.
     */
    if (file_basename_is(file, "arm64-v8a.so"))
        log_candidate(task, file, same_task, root_euid, app_process, lsposed_file);

    if (!same_task || !root_euid || !app_process || !lsposed_file)
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

    pr_info(DRIVER_NAME ": loaded in dry-run mode with candidate diagnostics; set bypass=1 only after match validation\n");
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
