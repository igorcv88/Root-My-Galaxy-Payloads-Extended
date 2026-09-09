# S938B ZZI4 LSPosed / DEFEX compatibility

One UI 9 enables Samsung DEFEX Immutable Root v2 on ZZI4. Hardware testing showed that DEFEX denied root `app_process64` access to `/data/adb/modules/zygisk_lsposed/zygisk/arm64-v8a.so`.

The exception was first validated as a standalone kprobe LKM with an exact match on current UID/EUID 0 `app_process64` plus the LSPosed Zygisk dentry tail. With the exception active, the DEFEX violation disappeared; new apps loaded LSPosed; after restarting zygote, `system_server` mapped the LSPosed native library and `LSPosedBridge` became active.

The permanent KernelSU Samsung DEFEX handler now applies that same narrow condition. It does not disable DEFEX globally and does not allow arbitrary `/data/adb` access.

Permanent module: `android15-6.6_kernelsu-pa3q-S938BXXUCZZI4-kdp-v3.3.0.ko`

- size: 3594000
- SHA-256: `d449605185e71f15f56163ddab2caf4fdc6833b35b5eaab0be6930d0d7153489`

Embedded ksud: `ksud-pa3q-S938BXXUCZZI4-kdp-v3.3.0`

- size: 6664656
- SHA-256: `d76b44c984b8d6f7121f712d8aa4e7cf0178ff36a8cd531bddaca9dd2fd361e2`
