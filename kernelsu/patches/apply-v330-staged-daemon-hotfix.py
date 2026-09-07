#!/usr/bin/env python3
from pathlib import Path

late_load = Path("userspace/ksud/src/late_load.rs")
utils = Path("userspace/ksud/src/utils.rs")

late_text = late_load.read_text(encoding="utf-8")
old_namespace = '''pub fn run(_package_name: &String, kmi: Option<String>, allow_shell: bool) -> Result<()> {
    info!("late-load command triggered!");
'''
new_namespace = '''fn acquire_rmg_late_load_lock() -> Result<std::fs::File> {
    // Never create/open a filesystem lock before KernelSU loads. Samsung
    // DEFEX/Safeplace can reject O_CREAT from this bootstrap execution context
    // even though the same process has uid 0. An abstract AF_UNIX address is
    // kernel-only, process-lifetime scoped, and still serializes auto/fallback
    // late-load callers across their separate mount namespaces.
    const LOCK_NAME: &[u8] = b"rmg_ksu_late_load_v1";
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);

    loop {
        let fd = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("Failed to create RMG abstract late-load lock socket");
        }

        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        address.sun_path[0] = 0;
        for (index, byte) in LOCK_NAME.iter().enumerate() {
            address.sun_path[index + 1] = *byte as libc::c_char;
        }
        let address_len = (
            std::mem::size_of::<libc::sa_family_t>() + 1 + LOCK_NAME.len()
        ) as libc::socklen_t;

        let bind_result = unsafe {
            libc::bind(
                fd,
                &address as *const libc::sockaddr_un as *const libc::sockaddr,
                address_len,
            )
        };
        if bind_result == 0 {
            let socket = unsafe {
                <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd)
            };
            return Ok(socket);
        }

        let error = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        if error.raw_os_error() != Some(libc::EADDRINUSE) {
            return Err(error).context("Failed to bind RMG abstract late-load lock socket");
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("Timed out waiting for another RMG late-load caller");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

pub fn run(_package_name: &String, kmi: Option<String>, allow_shell: bool) -> Result<()> {
    // Serialize every late-load caller without touching /data before KernelSU
    // policy is active. The socket fd stays alive until run() returns.
    let _late_load_lock = acquire_rmg_late_load_lock()?;
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .context("Failed to read kernel boot id for late-load")?
        .trim()
        .to_string();
    let ready_marker_path = "/data/local/tmp/.rmg-ksu-late-load-ready";

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

    // Keep the bootstrap in the private DEFEX trampoline namespace until the
    // KernelSU module has been loaded. In particular, do not call setns here:
    // this pre-KSU execution context can be killed by Samsung policy with
    // SIGSYS. No systemless/module mounts are created before the post-load
    // namespace switch below.
    info!("late-load command triggered!");
    dump_process_info("late-load bootstrap");
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

post_load_anchor = '''    // We need to reset stdin/stdout/stderr; otherwise, sending file descriptors via cmd transactions
    // will be blocked by SELinux because its fsec->sid is still u:r:su:s0 instead of u:r:ksu:s0.
'''
post_load_namespace = '''    // The RMG DEFEX trampoline deliberately execs ksud from a private mount
    // namespace so the temporary /system/bin/logcat bind never becomes global.
    // Only after kernelsu.ko is active do we enter init's mount namespace.
    // Everything that can create systemless/module mounts happens below this
    // point, so those mounts persist globally after the trampoline exits.
    let self_mnt_before = std::fs::read_link("/proc/self/ns/mnt")
        .context("Failed to read late-load mount namespace")?;
    let init_mnt = std::fs::read_link("/proc/1/ns/mnt")
        .context("Failed to read init mount namespace")?;
    dump_process_info("late-load before init namespace switch");
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
    dump_process_info("late-load after init namespace switch");

    // We need to reset stdin/stdout/stderr; otherwise, sending file descriptors via cmd transactions
    // will be blocked by SELinux because its fsec->sid is still u:r:su:s0 instead of u:r:ksu:s0.
'''
if late_text.count(post_load_anchor) != 1:
    raise SystemExit("expected v3.3.0 post-load reset-stdio anchor exactly once")
late_text = late_text.replace(post_load_anchor, post_load_namespace, 1)

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

print("Applied staged-daemon handoff + post-load init mount namespace hotfix")
