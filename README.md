<p align="center">
  <img src=".github/assets/root-my-galaxy-payloads-banner.svg" alt="Root My Galaxy Payloads Extended" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/igorcv88/Root-My-Galaxy-Extended/releases/latest"><img alt="App release" src="https://img.shields.io/github/v/release/igorcv88/Root-My-Galaxy-Extended?label=app" /></a>
  <img alt="Firmware" src="https://img.shields.io/badge/firmware-CZG3%20%2B%20ZZI4-59636e" />
  <img alt="Payload" src="https://img.shields.io/badge/payload-v0266%20%2F%20v0300-2f81f7" />
  <img alt="KernelSU" src="https://img.shields.io/badge/KernelSU-3.3.0-2f81f7" />
  <a href="https://github.com/igorcv88/Root-My-Galaxy-Payloads-Extended/actions/workflows/update-payloads.yml"><img alt="Payload build" src="https://img.shields.io/github/actions/workflow/status/igorcv88/Root-My-Galaxy-Payloads-Extended/update-payloads.yml?branch=main&amp;label=payloads" /></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/igorcv88/Root-My-Galaxy-Payloads-Extended" /></a>
</p>

<p align="center">
  <strong>Exact firmware profiles, CVE-2026-43499 payloads, root helper and Samsung KernelSU artifacts for the maintained Galaxy S25 Ultra targets.</strong>
</p>

<p align="center">
  <a href="https://github.com/igorcv88/Root-My-Galaxy-Extended">Root My Galaxy app</a>
  ·
  <a href="https://github.com/BuSung-dev/Root-My-Galaxy-Payloads">Upstream payloads</a>
  ·
  <a href="support/targets-v3.json">Current v3 feed</a>
</p>

## Root My Galaxy Payloads Extended

Based on [BuSung-dev's original payload repository](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads), this fork maintains Galaxy S25 Ultra firmware profiles, payloads, a root helper and Samsung-specific KernelSU artifacts for the companion app. Later firmware contributions and integration fixes are credited below.

| Component | Maintained here |
| --- | --- |
| Profiles | Separate firmware identities and matching artifacts |
| KernelSU | Samsung-specific 3.3.0 integration and firmware-specific fixes |
| Metadata | Artifact sizes, SHA-256 hashes and app-facing target policy |
| Publication | Consistency checks and preserved historical artifacts |

The Android interface, settings, Auto Root, Shizuku startup, history and recovery controls belong to the companion app. “Extended” describes this fork's additions, not compatibility with every Galaxy device.

<p align="center">
  <a href="#maintained-s938b-targets">Compatibility</a> ·
  <a href="#current-v3-feed">Artifacts</a> ·
  <a href="#target-agnostic-publication-workflow">Publication</a> ·
  <a href="#technical-documentation">Documentation</a> ·
  <a href="#credits-and-provenance">Credits</a>
</p>

> [!WARNING]
> These payloads use a kernel exploit. A failed run can panic or reboot the device. Use only on devices you own or are explicitly authorized to test.

## Maintained S938B targets

| Payload ID | Firmware / Android | Kernel | Generation | Current status |
| --- | --- | --- | --- | --- |
| `pa3q-S938BXXSBCZG3` | `S938BXXSBCZG3` / Android 16 API 36 | `6.6.98-android15-8-pd6ff1cd-abogkiS938BXXSBCZG3-4k` | `v0266` | Legacy maintained S938B profile |
| `pa3q-S938BXXUCZZI4` | `S938BXXUCZZI4` / Android 17 API 37 | `6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZI4-4k` | `v0300` | Current One UI 9 beta profile; exploit + KernelSU handoff hardware validated |

ZZI4 exact build display is `CP2A.260605.016.S938BXXUCZZI4`, SPL `2026-08-05`, `arm64-v8a`, 4K pages. Every profile is exact-match: firmware/kernel updates can invalidate offsets, KASLR behavior, physical addressing assumptions or the KernelSU module pair.

## Current v3 feed

`support/targets-v3.json` is the canonical app-facing manifest. Each profile publishes exact exploit, KernelSU and root-helper metadata plus a per-target exploit `routePolicy`.

### CZG3

| Artifact | Path | Size | SHA-256 |
| --- | --- | ---: | --- |
| Exploit | `artifacts/pa3q-S938BXXSBCZG3-v0266/cve-2026-43499-app.so` | 104128 | `1719e9362cd19e58521cb785fcaa40c4613ca854d0c3c9fb8320edf8e9046303` |
| Root helper | `artifacts/pa3q-S938BXXSBCZG3-v0266/cve-2026-43499-root` | 31496 | `788611baf566f0ca9008d28fa7d1b1edb4657efc56e4b5ac24b319ae12519dd4` |
| KernelSU | `kernelsu/ksud-s25u-kdp-v3.3.0` | 5101328 | `9c07ab0f9922cef5a8ef0c7805967d1019bf9e084553bc994e7a42c9347bdab1` |

Route policy:

```text
slideRoute=default
attempts=24
attemptTimeoutSec=120
p0AttemptTimeoutSec=45
p0OffsetCache=true
prefersShellTransport=false
```

### ZZI4

| Artifact | Path | Size | SHA-256 |
| --- | --- | ---: | --- |
| Exploit | `artifacts/pa3q-S938BXXUCZZI4-v0300/cve-2026-43499-app.so` | 104128 | `14143d6c5385e4c46bd34dc335772e9d1bcae7f5c102e34a6b142b875395df2b` |
| Root helper | `artifacts/pa3q-S938BXXUCZZI4-v0300/cve-2026-43499-root` | 31496 | `788611baf566f0ca9008d28fa7d1b1edb4657efc56e4b5ac24b319ae12519dd4` |
| KernelSU | `kernelsu/ksud-pa3q-S938BXXUCZZI4-kdp-v3.3.0` | 6663376 | `f1d466ad29bbeb472622d7e16aadc4fff11d4eec6fa61d46e104d347b65a8454` |

Route policy:

```text
slideRoute=auto
attempts=24
attemptTimeoutSec=120
p0AttemptTimeoutSec=45
p0OffsetCache=true
prefersShellTransport=true
```

The root helper is intentionally shared between these current S938B profiles; exploit and KernelSU artifacts remain target-specific.

## ZZI4 exploit port

ZZI4 is not a blind offset bump from CZG3. Android 17 / kernel 6.6.127 required a separate target derivation from the exact kernel Image/BTF and hardware validation of the KASLR/data-write route.

The current production target label is:

```text
pa3q-S938BXXUCZZI4-app-tracefs-phys-alias
```

The application payload enables:

- deterministic Tracefs KASLR discovery when shell transport can read Tracefs;
- `APP_TRACEFS_PHYS_ALIAS_DATA=1`, because the slide source and data-addressing mode are different concerns on this firmware;
- `APP_PHYS_P0_ORACLE=1` as the physical P0 oracle/fallback path;
- a bounded `APP_FOPS_RETRY_BUDGET=8`;
- shared writer state across FOPS shots so retries stop once a write actually lands;
- rotated trigger delays across retry shots.

The key hardware finding was that canonical direct-map writes did not land reliably on ZZI4, while physical-load-alias writes did. The current target therefore keeps Tracefs for slide discovery but addresses kernel data through the physical-load alias.

The current build has completed an on-device root run on SM-S938B/ZZI4 with Tracefs KASLR, `data_mode=physical-alias`, `window=1`, a landed physical write and complete KernelSU activation in supervisor attempt 1.

The more invasive sync-pselect synchronization experiment remains parked. It is not part of the current payload and should only be reconsidered if repeated hardware runs show `source=tracefs`, physical-alias addressing and rotating FOPS shots but persistent `window=0` failures.

## Root helper and KernelSU handoff

After bootstrap UID 0 lands, the root helper can perform the KernelSU handoff immediately instead of relying on a second app round trip.

The S938B flow preserves the Samsung-specific invariants needed for KDP/RKP/DEFEX and Safeplace-style restrictions:

```text
exploit obtains bootstrap UID 0
        ↓
verified ksud is pre-staged
        ↓
DEFEX-safe bind execution over /system/bin/logcat
        ↓
ksud late-load --allow-shell
        ↓
switch into PID1 mount namespace
        ↓
KernelSU/module mount stages complete globally
        ↓
boot-scoped readiness marker published
```

The app retains a serialized client `--late-load` fallback when auto-late-load does not reach global readiness, but the custom KernelSU patch serializes callers and suppresses same-boot lifecycle replay.

## ZZI4 staged-daemon hotfix

ZZI4 keeps a firmware-sensitive KernelSU 3.3.0 userspace/module pair and the S938B staged-daemon hotfix.

The hotfix exists because early ZZI4 bring-up exposed two important failure modes: Samsung security policy could reject pre-KernelSU filesystem operations/opening the running executable, and module/systemless mounts created inside the private DEFEX trampoline namespace would disappear when that namespace exited.

The current fix therefore:

- serializes late-load through an abstract AF_UNIX lock, avoiding a pre-KernelSU filesystem lock;
- reads the kernel `boot_id` and skips duplicate late-load stage replay on the same boot;
- switches from the private trampoline mount namespace into PID1's mount namespace before owning module/systemless mounts;
- stages the daemon from a verified pre-uploaded `/data/local/tmp/.ksud-stage` via rename rather than reopening `/proc/self/exe` under the bootstrap security context;
- publishes `/data/local/tmp/.rmg-ksu-late-load-ready` only after blocking mount stages complete.

These behaviors are part of the KernelSU artifact itself. App-side post-root automation must not replace `/data/adb/ksud`, restage `.ksud-stage`, or invoke another unsynchronized late-load sequence.

## Why ZZI4 KernelSU is not rebuilt by generic CI

`.github/build-targets.json` declares ZZI4 with:

```json
"kernelSu": null
```

That is intentional. The ZZI4 module/ksud pair is hand-built/non-LTO/symbol-pinned and must be preserved rather than silently regenerated by generic CI. Payload/root-helper publication can still be automated for the target while the known-good KernelSU pair remains immutable unless a deliberate rebuild procedure is performed.

CZG3 retains an automated KernelSU build descriptor because its pair is reproducible through the configured DDK path.

## Target-agnostic publication workflow

`Atualizar Payloads` is no longer hardcoded to one firmware. The workflow plans one or all declared build targets from `.github/build-targets.json`, records a single source commit, and all matrix build jobs check out that exact revision.

Publication then re-checks `origin/main` before mutation and immediately before commit/push. If `main` advanced, publication aborts and requires a rerun instead of rebasing stale binaries onto newer source.

For changed artifacts it refreshes target metadata, `support/targets-v3.json`, root-helper sidecars and existing per-target aggregate `SHA256SUMS` files. The historical CZG3 rebuild trigger remains explicitly scoped to CZG3.

This means a ZZI4 source update cannot accidentally rebuild the hand-built KernelSU pair, and a concurrent merge cannot silently publish artifacts produced from an older source tree.

## Feed/app contract

The companion app treats the feed as authoritative target data rather than embedding firmware route choices in application code.

The feed currently supplies:

- exact device/build/kernel identity;
- exploit artifact URL/size/SHA-256;
- KernelSU artifact URL/size/SHA-256;
- root-helper URL/size/SHA-256;
- `routePolicy` for Manual and Auto Root.

The app's last-known-good offline cache is bound to the full target set and route policy. A hash-identical artifact can therefore be refreshed when only route policy changes.

## Legacy artifacts

Historical artifacts remain separate from current versioned directories. Updating `v0266` or `v0300` must not overwrite immutable legacy paths consumed by older clients.

The publication validators preserve that separation and fail closed on artifact/feed inconsistencies.

## Technical documentation

- [Support feed and matching rules](support/README.md)
- [Firmware-to-profile porting procedure](docs/PORTING.md)
- [Samsung KernelSU late-load builds](kernelsu/README.md)
- `analysis/SM-S938B-S938BXXSBCZG3/` — CZG3 derivation/history
- `src/targets/pa3q-S938BXXUCZZI4/` — current ZZI4 target constants and physical-alias policy
- `kernelsu/patches/KernelSU-v3.3.0-s938b-staged-daemon-hotfix.patch` — S938B late-load namespace/staging hotfix

## Credits and provenance

This repository is a derivative work assembled from several upstream projects and individual contributions.

- **[BuSung-dev/Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads)** — upstream payload/feed structure, build tooling and Samsung target integration.
- **[BuSung-dev/Root-My-Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy)** — companion application and original Root My Galaxy architecture.
- **[mitschud](https://github.com/mitschud)** / **[upstream PR #300](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads/pull/300)** — Galaxy S25 kernel-6.6.127 Tracefs KASLR contribution, root-helper auto-late-load pattern and writer timing reference used by the ZZI4 port.
- **[NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia/tree/main/IonStack/CVE-2026-43499/exploit)** — published CVE-2026-43499 exploit source forming the exploit lineage.
- **[KernelSU](https://github.com/tiann/KernelSU)** by tiann and contributors — kernel root framework, `ksud` late-load, module lifecycle and native userspace soft-reboot behavior consumed by the companion app.
- **[HyperRamzey/Root-My-Galaxy](https://github.com/HyperRamzey/Root-My-Galaxy)** — reference for the app-side persistent local ADB/Shizuku and post-root coordination architecture.

Each upstream project and contribution remains subject to its own license and copyright notices. This repository is distributed under [LICENSE](LICENSE).
