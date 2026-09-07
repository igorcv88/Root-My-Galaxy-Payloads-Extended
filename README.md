<p align="center">
  <img src=".github/assets/root-my-galaxy-payloads-banner.svg" alt="Root My Galaxy Payloads" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/igorcv88/Root-My-Galaxy-S938B/releases/latest"><img alt="App release" src="https://img.shields.io/github/v/release/igorcv88/Root-My-Galaxy-S938B?label=app" /></a>
  <img alt="Firmware" src="https://img.shields.io/badge/firmware-S938BXXSBCZG3-59636e" />
  <img alt="Payload" src="https://img.shields.io/badge/payload-v0266-2f81f7" />
  <img alt="KernelSU" src="https://img.shields.io/badge/KernelSU-3.3.0-2f81f7" />
  <a href="https://github.com/igorcv88/Root-My-Galaxy-Payloads-S938B/actions/workflows/update-payloads.yml"><img alt="Payload build" src="https://img.shields.io/github/actions/workflow/status/igorcv88/Root-My-Galaxy-Payloads-S938B/update-payloads.yml?branch=main&amp;label=payloads" /></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/igorcv88/Root-My-Galaxy-Payloads-S938B" /></a>
</p>

<p align="center">
  <strong>Firmware profile, exploit, root helper and KernelSU artifacts for the maintained Root My Galaxy S25 Ultra target.</strong>
</p>

<p align="center">
  <a href="https://github.com/igorcv88/Root-My-Galaxy-S938B">Root My Galaxy app</a>
  ·
  <a href="https://github.com/BuSung-dev/Root-My-Galaxy-Payloads">Upstream payloads</a>
  ·
  <a href="support/targets-v3.json">Current v3 feed</a>
</p>

> [!WARNING]
> These payloads use a kernel exploit. A failed run can panic/reboot the device. Use only on devices you own or are explicitly authorized to test.

## Maintained target

| | Configuration |
| --- | --- |
| Device | Samsung Galaxy S25 Ultra `SM-S938B` (`pa3q`) |
| Firmware | `S938BXXSBCZG3` |
| Build display | `BP4A.251205.006.S938BXXSBCZG3` |
| Android | Android 16 / API 36 |
| Kernel | `6.6.98-android15-8-pd6ff1cd-abogkiS938BXXSBCZG3-4k` |
| ABI / page size | `arm64-v8a` / 4K |
| Current exploit generation | `v0266` |
| KernelSU userspace | `3.3.0 / 32601` |

A firmware or kernel update can invalidate the profile and its offsets.

## Current v0266 artifacts

The current v3 feed publishes a three-artifact set for CZG3:

| Artifact | Path | Size | SHA-256 |
| --- | --- | ---: | --- |
| Exploit | `artifacts/pa3q-S938BXXSBCZG3-v0266/cve-2026-43499-app.so` | 104128 | `ae4fffba942a131f6c9fa144f7406a0a337638c8b5b660feb04e9c7c9b5555b4` |
| Root helper | `artifacts/pa3q-S938BXXSBCZG3-v0266/cve-2026-43499-root` | 28704 | `0b4a12341225526a6e26daa9db2ba9615e7203b862a68b502fd4030c09a671c9` |
| KernelSU | `kernelsu/ksud-s25u-kdp-v3.3.0` | 5096104 | `5a009f1fc58b25a6e197d8ec951a86ec11a9b5ec9d56bdb5f7a3410a22b9b48a` |

The app release workflow pins the payload repository to a specific commit, verifies the root-helper size/SHA-256 from the feed and embeds that exact helper into the APK.

## What v0266 changes

v0266 is intentionally narrow. It keeps the restored minimal CZG3 exploit race and adds only changes with a clear reliability or handoff purpose.

### Tracefs KASLR route

The existing application-payload Tracefs slide implementation is enabled for CZG3 with event ID **109**. The goal is to obtain a deterministic KASLR slide when the execution context is allowed to use Tracefs.

The physical/P0 route remains available as fallback. v0266 therefore does not assume Tracefs access from every Android SELinux domain.

### Root-helper auto-late-load

After bootstrap root lands, the root helper can immediately perform the KernelSU handoff itself rather than waiting for a second app/client command.

The adapted sequence is:

```text
exploit obtains UID 0
        ↓
stage ksud / prepare /data/adb
        ↓
private mount namespace
        ↓
bind ksud over /system/bin/logcat
        ↓
ksud late-load --allow-shell
        ↓
KernelSU active / SELinux restored
        ↓
loader remains as daemon
```

This removes the client round-trip race between exploit success and late-load. The app still retains an explicit `--late-load` fallback if auto-late-load is not ready.

### DEFEX-safe execution

The helper executes the staged loader through a bind mount over `/system/bin/logcat` inside a private mount namespace rather than directly executing a `/data` path. This is retained specifically for Samsung DEFEX/Safeplace-style restrictions.

### `--allow-shell`

KernelSU is late-loaded with `--allow-shell`, allowing the authenticated ADB shell used by the companion app's post-root automation to obtain KernelSU root. This is a post-root capability; the exploit itself remains standalone when Auto Root runs.

### Daemon-stay and post-root markers

The helper remains alive as the KernelSU daemon after late-load so the root handoff is not tied to the lifetime of the app/ADB client. Lightweight post-root markers and `ksu_late_load.log` document the late-load stages without inserting structured instrumentation into the FOPS race.

## What v0266 deliberately does not change

The CZG3 production path still avoids the experimental instrumentation that previously affected reliability. v0266 does **not** reintroduce:

- External Observer coupling;
- `czg3_diag` race instrumentation;
- pselect state gates;
- Auto SIGRETURN interception;
- global syscall wrappers;
- keeper-guard race telemetry;
- broad timing sweeps or new FOPS mutations.

The existing FOPS timing/retry behavior is kept separate from the Tracefs and KernelSU handoff changes so hardware validation can identify which layer actually changed.

## Support feed and helper binding

`support/targets-v3.json` now carries `exploit`, `kernelsu` and `rootHelper` metadata, each with URL, exact size and SHA-256.

This matters because the root helper is no longer just a generic APK implementation detail: v0266 helper behavior and v0266 exploit behavior are a matched generation. The app therefore fails closed if its bundled helper does not match the profile.

A last-known-good offline cache in the app is also keyed by all three digests. Pre-v0266 caches without helper metadata must be refreshed through a successful Manual Online run.

## Auto Root relationship

This repository does not itself schedule Auto Root. The companion app does that. Its intended policy is:

- Auto Root uses only the last-known-good offline set;
- Auto Root is always Standalone for root acquisition;
- no network, Shizuku or Wireless ADB dependency is introduced into the exploit race;
- post-root ADB/Shizuku automation starts only after KernelSU has been verified.

## Legacy artifacts

The hardware-validated legacy v2 artifact remains immutable at its historical path for previously released clients. v0266 uses a separate versioned artifact directory and must not overwrite the v2 payload.

The workflow validator checks this separation before publication.

## Building and publishing

Use the `Atualizar Payloads` workflow on `main`. For an exploit update it:

1. builds the CZG3 app payload and matching root helper with the pinned Android NDK;
2. verifies expected artifact size and feed invariants;
3. publishes the versioned v0266 exploit and helper;
4. updates `support/targets-v3.json` with exact hashes;
5. validates that legacy v2 is unchanged.

The companion app should only be released after this workflow has published the new helper metadata, because the app release workflow consumes that feed to embed the matching helper.

## Technical documentation

- [Support feed and matching rules](support/README.md)
- [Firmware-to-profile porting procedure](docs/PORTING.md)
- [Samsung KernelSU late-load builds](kernelsu/README.md)
- `analysis/SM-S938B-S938BXXSBCZG3/` contains the CZG3 derivation and v0266 rollout notes.

## Credits and provenance

This repository is a derivative work assembled from several upstream projects and individual contributions. The following sources materially underpin the current implementation:

- **[BuSung-dev/Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads)** — upstream payload/feed structure, build tooling and Samsung target integration.
- **[BuSung-dev/Root-My-Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy)** — companion application and the original Root My Galaxy project architecture.
- **[mitschud](https://github.com/mitschud)** / **[upstream PR #300](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads/pull/300)** — the hardware-tested Galaxy S25 `6.6.127` contribution from which the Tracefs KASLR route and root-helper auto-late-load pattern were adapted: event ID 109, `--allow-shell`, DEFEX-safe `/system/bin/logcat` bind execution, daemon-stay and late-load step markers.
- **[NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia/tree/main/IonStack/CVE-2026-43499/exploit)** — published CVE-2026-43499 exploit source forming the exploit lineage used by Root My Galaxy.
- **[KernelSU](https://github.com/tiann/KernelSU)** by tiann and contributors — kernel root framework and `ksud` late-load/userspace lifecycle.
- **[HyperRamzey/Root-My-Galaxy](https://github.com/HyperRamzey/Root-My-Galaxy)** — companion-fork work used on the app side for persistent local ADB/Shizuku and post-root lifecycle behavior; its device-tested lifecycle informed how v0266's `--allow-shell` handoff is consumed.

Each upstream project and contribution remains subject to its own license and copyright notices. This repository is distributed under the license in [LICENSE](LICENSE).
