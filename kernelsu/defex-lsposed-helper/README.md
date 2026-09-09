# ZZI4 LSPosed DEFEX compatibility helper

Target: `SM-S938B`, `S938BXXUCZZI4`, kernel `6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZI4-4k`.

This is a temporary test module for the One UI 9 beta 2 regression where Samsung DEFEX Immutable Root rejects Zygisk/LSPosed reads of:

```text
/data/adb/modules/zygisk_lsposed/zygisk/arm64-v8a.so
```

The helper registers a second kprobe on `task_defex_enforce`. It does nothing by default (`bypass=0`). A match requires all of the following:

- `task == current`;
- current effective UID is root;
- current executable is `bin/app_process64`;
- target file resolves to the exact dentry tail `adb/modules/zygisk_lsposed/zygisk/arm64-v8a.so`.

Only after `bypass=1` is explicitly set does the pre-handler replace the DEFEX task argument with `NULL`, matching the technique already used by the repository's Samsung KernelSU compatibility patch for KSU-domain tasks.

## Build

Run the GitHub Actions workflow `Build ZZI4 DEFEX LSPosed helper`. The workflow uses the existing Android 15/6.6 DDK image and forces the exact ZZI4 release string. It uploads:

```text
defex_lsposed_compat.ko
defex_lsposed_compat.ko.sha256
```

The module must report the exact vermagic:

```text
6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZI4-4k SMP preempt mod_unload modversions aarch64
```

## On-device staged test

Load in dry-run mode first:

```sh
su
insmod /path/to/defex_lsposed_compat.ko
cat /sys/module/defex_lsposed_compat/parameters/bypass
dmesg | grep -F defex_lsposed_compat | tail -n 20
```

Expected initial parameter value:

```text
N
```

Generate a fresh zygote child without restarting the framework:

```sh
am force-stop com.android.settings
am start -a android.settings.SETTINGS
sleep 3
dmesg | grep -E 'defex_lsposed_compat|DEFEX.*zygisk_lsposed' | tail -n 30
```

A dry-run match should log:

```text
defex_lsposed_compat: matched ... bypass=0
```

DEFEX should still deny the LSPosed library in dry-run mode.

If the match is correct, enable the narrow bypass at runtime:

```sh
echo 1 > /sys/module/defex_lsposed_compat/parameters/bypass
cat /sys/module/defex_lsposed_compat/parameters/bypass
```

Expected value:

```text
Y
```

Generate another fresh process and inspect both DEFEX and Zygisk logs:

```sh
am force-stop com.android.settings
am start -a android.settings.SETTINGS
sleep 3

dmesg | grep -E 'defex_lsposed_compat|DEFEX.*zygisk_lsposed' | tail -n 40
logcat -d -v threadtime | grep -E 'zygisk_lsposed|pread_full|read ehdr|preload failed|not preloaded|dlopen' | tail -n 100
```

Do not restart zygote/system_server until this A/B test shows that new LSPosed loads are no longer rejected by DEFEX.

Unload at any time with:

```sh
rmmod defex_lsposed_compat
```

This helper is intentionally not wired into the persistent KernelSU payload. If validated on hardware, port the same narrow match into `kernelsu/patches/KernelSU-v3.3.0-samsung-kdp-rkp-defex.patch` and remove the helper.
