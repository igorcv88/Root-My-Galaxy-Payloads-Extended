# SM-S938B CZG3 KernelSU v3.3.0 late-load contract

The SM-S938B/CZG3 Android 16 bootstrap-root path must not stage the running `ksud` by copying `/proc/self/exe` into `/data/adb/ksud` before the KernelSU module is loaded. On this Samsung target that read/copy can be rejected with `EPERM` by the pre-KernelSU security environment.

The v3.3.0 userspace hotfix therefore consumes `/data/local/tmp/.ksud-stage` with `stage_daemon_from()`, atomically renaming it to `/data/adb/ksud`, then applying root ownership and mode `0755`. This restores the handoff used by the known-working Samsung v3.2.5 path without changing the official KernelSU v3.3.0 version count.

## Standalone Auto Root handoff

Standalone Auto Root intentionally runs as the ordinary application UID and cannot depend on ADB/Shizuku or write `/data/local/tmp` before root exists. The app therefore prepares the already feed-verified `ksud` before launching the exploit at:

`/data/user/0/dev.busung.s25uroot/files/ksu-bootstrap/ksud-s25u-kdp`

The root helper links `src/ksu_bootstrap.c`. Its constructor runs only for the UID-0 `--umh` invocation, after the exploit race has already succeeded. It validates the expected v3.3.0 file size, copies the app-private source atomically to `/data/local/tmp/ksud-s25u-kdp`, creates `/data/local/tmp/.ksud-stage`, and only then lets the existing DEFEX-safe auto-late-load path proceed. If the verified source cannot be staged, stale `/data/local/tmp` loader/stage files are removed instead of being reused.

This staging happens entirely after the exploit/KASLR/FOPS race and does not alter its timing.

Current rebuilt CZG3 KernelSU artifacts:

- `android15-6.6_kernelsu-s25u-kdp-v3.3.0.ko`: 332416 bytes, SHA-256 `49ea9b561e29dd4f73d626c76978ac5b87d4bbd8f43b607e3b43186385875d8d`
- `ksud-s25u-kdp-v3.3.0`: 5096104 bytes, SHA-256 `5a009f1fc58b25a6e197d8ec951a86ec11a9b5ec9d56bdb5f7a3410a22b9b48a`

The `ksud` artifact must stay synchronized with `support/targets-v3.json`, the app's embedded Auto Root manifest, and `KSU_EXPECTED_SIZE` in `src/ksu_bootstrap.c`.
