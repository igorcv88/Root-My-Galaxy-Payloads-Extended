#!/usr/bin/env python3
from pathlib import Path

late_load = Path("userspace/ksud/src/late_load.rs")
utils = Path("userspace/ksud/src/utils.rs")

late_text = late_load.read_text(encoding="utf-8")
old_namespace = '''pub fn run(_package_name: &String, kmi: Option<String>, allow_shell: bool) -> Result<()> {
    info!("late-load command triggered!");
'''
new_namespace = '''pub fn run(_package_name: &String, kmi: Option<String>, allow_shell: bool) -> Result<()> {
    // Serialize every late-load caller. The UMH auto path and the app fallback
    // can overlap while the kernel control channel is already visible but the
    // blocking mount stages are still running. Holding this lock until the end
    // prevents duplicate module/metamodule stage replay.
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .context("Failed to read kernel boot id for late-load")?
        .trim()
        .to_string();
    let ready_marker_path = "/data/local/tmp/.rmg-ksu-late-load-ready";
    let late_load_lock = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open("/data/local/tmp/.rmg-ksu-late-load.lock")
        .context("Failed to open RMG late-load lock")?;
    rustix::fs::flock(&late_load_lock, rustix::fs::FlockOperation::LockExclusive)
        .context("Failed to acquire RMG late-load lock")?;

    // A second caller can only observe this marker after the first caller has
    // completed late-load, metamodule and post-mount stages. Do not replay the
    // stages on the same kernel boot.
    let expected_boot_line = format!("boot_id={boot_id}");
    if std::fs::read_to_string(ready_marker_path)
        .ok()
        .is_some_and(|marker| marker.lines().any(|line| line.trim() == expected_boot_line))
    {
        info!("late-load already completed for boot_id={boot_id}; skipping duplicate caller");
        return Ok(());
    }

    // The RMG DEFEX trampoline deliberately execs ksud from a private mount
    // namespace so the temporary /system/bin/logcat bind never becomes global.
    // Late-load itself, however, owns systemless/module mounts and must run in
    // init's namespace or those mounts disappear with the trampoline namespace.
    let self_mnt_before = std::fs::read_link("/proc/self/ns/mnt")
        .context("Failed to read late-load mount namespace")?;
    let init_mnt = std::fs::read_link("/proc/1/ns/mnt")
        .context("Failed to read init mount namespace")?;
    utils::switch_mnt_ns(1).context("Failed to enter init mount namespace for late-load")?;
    let self_mnt_after = std::fs::read_link("/proc/self/ns/mnt")
        .context("Failed to verify late-load mount namespace")?;
    anyhow::ensure!(
        self_mnt_after == init_mnt,
        "late-load mount namespace mismatch after switch: self={} init={}",
        self_mnt_after.display(),
        init_mnt.display()
    );

    info!(
        "late-load mount namespace: before={} init={} after={}",
        self_mnt_before.display(),
        init_mnt.display(),
        self_mnt_after.display()
    );
    info!("late-load command triggered!");
'''
if late_text.count(old_namespace) != 1:
    raise SystemExit("expected Samsung v3.3.0 late-load entry anchor exactly once")
late_text = late_text.replace(old_namespace, new_namespace, 1)

old_late = '''    // Copy the daemon before loading the module changes this process's
    // security context. The remaining install steps require KernelSU policy.
    utils::stage_daemon().context("Failed to stage the running ksud")?;
'''
new_late = '''    // The app/helper pre-uploads a verified copy specifically for the privileged
    // handoff. Renaming it avoids reopening /proc/self/exe as bootstrap root,
    // which Samsung DEFEX/Safeplace can reject with EPERM before KernelSU loads.
    utils::stage_daemon_from("/data/local/tmp/.ksud-stage")
        .context("Failed to stage the pre-uploaded ksud")?;
'''
if late_text.count(old_late) != 1:
    raise SystemExit("expected v3.3.0 running-ksud staging block exactly once")
late_text = late_text.replace(old_late, new_late, 1)

old_ready = '''    // 13. Execute boot-completed stage scripts (non-blocking)
    init_event::run_stage("boot-completed", false);

    Ok(())
}
'''
new_ready = '''    // 13. Execute boot-completed stage scripts (non-blocking)
    init_event::run_stage("boot-completed", false);

    // Publish readiness only after all blocking mount stages completed in the
    // init namespace. The boot id makes the marker safe across full reboots.
    let ready_mnt = std::fs::read_link("/proc/self/ns/mnt")
        .unwrap_or_else(|_| self_mnt_after.clone());
    let ready_marker = format!(
        "boot_id={}\\nmount_ns={}\\n",
        boot_id,
        ready_mnt.display()
    );
    match std::fs::write(ready_marker_path, ready_marker) {
        Ok(()) => info!(
            "late-load global readiness published boot_id={} mount_ns={}",
            boot_id,
            ready_mnt.display()
        ),
        Err(e) => warn!("failed to publish late-load readiness marker: {e}"),
    }

    Ok(())
}
'''
if late_text.count(old_ready) != 1:
    raise SystemExit("expected Samsung v3.3.0 late-load completion anchor exactly once")
late_load.write_text(late_text.replace(old_ready, new_ready, 1), encoding="utf-8")

utils_text = utils.read_text(encoding="utf-8")
old_imports = '''use rustix::fs::{Mode, OFlags, open};
use rustix::process::setpgid;
use rustix::stdio::{dup2_stderr, dup2_stdin, dup2_stdout};
'''
new_imports = '''use rustix::fs::{Mode, OFlags, chown, open};
use rustix::process::setpgid;
use rustix::stdio::{dup2_stderr, dup2_stdin, dup2_stdout};
use rustix::thread::{Gid, Uid};
'''
if utils_text.count(old_imports) != 1:
    raise SystemExit("expected v3.3.0 rustix import block exactly once")
utils_text = utils_text.replace(old_imports, new_imports)

anchor = '''pub fn finish_install(libadbroot: Option<PathBuf>, data_path: Option<PathBuf>) -> Result<()> {
'''
staged_fn = '''pub fn stage_daemon_from(staged_exe: impl AsRef<Path>) -> Result<()> {
    ensure_dir_exists(defs::ADB_DIR)?;
    let staged_exe = staged_exe.as_ref();

    if !staged_exe.is_file() {
        bail!("{} is not a staged ksud file", staged_exe.display());
    }

    // Both paths live on /data, so rename performs the handoff without opening
    // the executable for a second read. This restores the hardware-proven
    // Samsung v3.2.5 handoff and atomically replaces an older daemon.
    std::fs::rename(staged_exe, defs::DAEMON_PATH).with_context(|| {
        format!(
            "Failed to rename {} to {}",
            staged_exe.display(),
            defs::DAEMON_PATH
        )
    })?;
    chown(defs::DAEMON_PATH, Some(Uid::ROOT), Some(Gid::ROOT))?;
    #[cfg(unix)]
    set_permissions(defs::DAEMON_PATH, Permissions::from_mode(0o755))?;
    Ok(())
}

'''
if utils_text.count(anchor) != 1:
    raise SystemExit("expected v3.3.0 finish_install anchor exactly once")
if "pub fn stage_daemon_from(" in utils_text:
    raise SystemExit("stage_daemon_from already present before hotfix")
utils_text = utils_text.replace(anchor, staged_fn + anchor)
utils.write_text(utils_text, encoding="utf-8")

print("Applied staged-daemon handoff + serialized init mount namespace hotfix")
