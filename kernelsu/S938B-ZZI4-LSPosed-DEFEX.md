# S938B ZZI4 LSPosed / DEFEX compatibility

One UI 9 enables Samsung DEFEX Immutable Root v2 on ZZI4. Hardware testing showed that DEFEX denied root `app_process64` access to `/data/adb/modules/zygisk_lsposed/zygisk/arm64-v8a.so`.

The exception was first validated as a standalone kprobe LKM with an exact match on current UID/EUID 0 `app_process64` plus the LSPosed Zygisk dentry tail. In dry-run mode the helper matched the denied `ch_zygote` call immediately before the DEFEX Immutable Root violation. With the narrow bypass enabled, the same call matched without a subsequent DEFEX violation; unrelated `zygiskd64` calls were observed with `app64=0` and were not bypassed.

After the bypass was enabled, newly forked apps loaded LSPosed. A controlled zygote restart then recreated the framework under the exception: `system_server` mapped `/data/adb/modules/zygisk_lsposed/zygisk/arm64-v8a.so`, logcat showed `LSPosedBridge`, and LSPosed was confirmed working on S938BXXUCZZI4 hardware.

The permanent KernelSU Samsung DEFEX handler applies that same narrow condition. It preserves the existing KSU-domain exception, does not disable DEFEX globally, and does not allow arbitrary `/data/adb` access.

Permanent module: `android15-6.6_kernelsu-pa3q-S938BXXUCZZI4-kdp-v3.3.0.ko`

- size: 3594000
- SHA-256: `d449605185e71f15f56163ddab2caf4fdc6833b35b5eaab0be6930d0d7153489`
- exact release: `6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZI4-4k`
- upstream-shaped, unstripped, no-LTO, with `.BTF` and `__versions` retained

Embedded ksud: `ksud-pa3q-S938BXXUCZZI4-kdp-v3.3.0`

- size: 6664656
- SHA-256: `d76b44c984b8d6f7121f712d8aa4e7cf0178ff36a8cd531bddaca9dd2fd361e2`

The standalone `defex_lsposed_compat` module remains only as a regression/diagnostic harness. It is not required once a root session is created with the permanent KernelSU/ksud pair above.
