#!/usr/bin/env python3
from pathlib import Path

path = Path("kernel/compat/samsung_defex.c")
text = path.read_text(encoding="utf-8")

include_anchor = "#include <linux/cred.h>\n#include <linux/errno.h>\n#include <linux/kprobes.h>\n#include <linux/sched.h>\n"
include_replacement = "#include <linux/cred.h>\n#include <linux/dcache.h>\n#include <linux/errno.h>\n#include <linux/fs.h>\n#include <linux/kprobes.h>\n#include <linux/sched.h>\n#include <linux/string.h>\n"
if include_anchor not in text:
    raise SystemExit("Samsung DEFEX include block not found")
text = text.replace(include_anchor, include_replacement, 1)

old_handler = '''static int ksu_samsung_defex_pre_handler(struct kprobe *probe, struct pt_regs *regs)
{
    struct task_struct *task = (struct task_struct *)regs->regs[0];

    (void)probe;
    if (task == current && current_uid().val == 0 && is_ksu_domain())
        regs->regs[0] = 0;

    return 0;
}
'''

new_handler = r'''/*
 * One UI 9 / Android 17 enables DEFEX Immutable Root v2 on the S938B ZZI4
 * kernel.  In that configuration app_process64 is denied opening the LSPosed
 * Zygisk library from /data/adb even though Zygisk itself is already running
 * with the expected root transition.  Keep the exception deliberately narrow:
 * current root app_process64 + the exact LSPosed Zygisk library dentry tail.
 *
 * This condition was hardware-validated on S938BXXUCZZI4 before being folded
 * into the KernelSU Samsung compatibility layer.  No generic /data/adb,
 * app_process64, or DEFEX bypass is introduced.
 */
static bool ksu_defex_qstr_eq(const struct qstr *q, const char *s)
{
    size_t len;

    if (!q || !q->name || !s)
        return false;

    len = strlen(s);
    return q->len == len && !memcmp(q->name, s, len);
}

static bool ksu_defex_is_lsposed_zygisk_so(const struct file *file)
{
    struct dentry *d;

    if (!file)
        return false;

    d = file->f_path.dentry;
    if (!d || !ksu_defex_qstr_eq(&d->d_name, "arm64-v8a.so"))
        return false;

    d = d->d_parent;
    if (!d || !ksu_defex_qstr_eq(&d->d_name, "zygisk"))
        return false;

    d = d->d_parent;
    if (!d || !ksu_defex_qstr_eq(&d->d_name, "zygisk_lsposed"))
        return false;

    d = d->d_parent;
    if (!d || !ksu_defex_qstr_eq(&d->d_name, "modules"))
        return false;

    d = d->d_parent;
    return d && ksu_defex_qstr_eq(&d->d_name, "adb");
}

static bool ksu_defex_is_app_process64(const struct task_struct *task)
{
    const struct file *exe;
    struct dentry *d;

    if (!task || !task->mm)
        return false;

    exe = READ_ONCE(task->mm->exe_file);
    if (!exe)
        return false;

    d = exe->f_path.dentry;
    if (!d || !ksu_defex_qstr_eq(&d->d_name, "app_process64"))
        return false;

    d = d->d_parent;
    return d && ksu_defex_qstr_eq(&d->d_name, "bin");
}

static int ksu_samsung_defex_pre_handler(struct kprobe *probe, struct pt_regs *regs)
{
    struct task_struct *task = (struct task_struct *)regs->regs[0];
    struct file *file = (struct file *)regs->regs[1];

    (void)probe;

    if (task != current)
        return 0;

    if (current_uid().val == 0 && is_ksu_domain()) {
        regs->regs[0] = 0;
        return 0;
    }

    if (uid_eq(current_euid(), GLOBAL_ROOT_UID) &&
        ksu_defex_is_app_process64(current) &&
        ksu_defex_is_lsposed_zygisk_so(file))
        regs->regs[0] = 0;

    return 0;
}
'''

if old_handler not in text:
    raise SystemExit("Samsung DEFEX pre-handler block not found")
text = text.replace(old_handler, new_handler, 1)

old_log = '    pr_info("Samsung DEFEX credential synchronization and KSU-task bypass enabled\\n");'
new_log = '    pr_info("Samsung DEFEX credential synchronization, KSU-task bypass, and LSPosed app_process64 exception enabled\\n");'
if old_log not in text:
    raise SystemExit("Samsung DEFEX init log anchor not found")
text = text.replace(old_log, new_log, 1)

path.write_text(text, encoding="utf-8")
print("Applied narrow LSPosed DEFEX compatibility exception")
