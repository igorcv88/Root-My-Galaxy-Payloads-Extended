# Root My Galaxy Payloads Extended

Root My Galaxy Payloads Extended is the companion repository for [Root My Galaxy Extended](https://github.com/igorcv88/Root-My-Galaxy-Extended). Based on [BuSung-dev/Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads), it contains maintained Galaxy S25 Ultra firmware profiles, kernel-exploit payloads, a root helper and Samsung-specific KernelSU artifacts.

The original BuSung repository is the upstream reference. This fork combines its structure with later firmware work and integration fixes from the contributors credited below. The Android interface, settings, history, Shizuku startup and recovery controls belong to the companion app.

## What this fork maintains

- Separate Galaxy S25 Ultra firmware profiles and their matching payload/KernelSU artifacts.
- Samsung-specific KernelSU 3.3.0 integration, including firmware-specific fixes.
- Metadata describing supported builds, artifact sizes and SHA-256 hashes.
- Publication checks that keep profiles and binaries consistent and preserve historical artifacts for older clients.

These additions include adapted work from upstream and other forks. The repository is not a general-purpose KernelSU distribution or a claim of support for every Samsung device.

## Compatibility and limitations

The maintained scope described here is **Galaxy S25 Ultra SM-S938B**.

| Firmware | Android | Kernel series | Repository status |
| --- | --- | --- | --- |
| S938BXXSBCZG3 | 16 | 6.6.98 | Maintained earlier profile |
| S938BXXUCZZI4 | 17 / One UI 9 beta | 6.6.127 | Profile with reported on-device validation |

Profiles depend on an exact firmware/kernel match. The same model name, Android version or kernel series is insufficient to establish compatibility. Older or inherited files elsewhere in this repository do not expand the maintained scope in this table.

The documented KernelSU integration is **3.3.0**; compatibility with 3.4 is not established here. Reported on-device validation does not guarantee success or compatibility after a system update.

> [!WARNING]
> These files use a kernel exploit. Failure can freeze or reboot the phone and lose unsaved work. Keep backups and use only devices you own or are authorized to test. Hash verification detects file mismatches; it does not make execution safe.

## Artifact maintenance

The app and this repository share versioned metadata for device identity and matching artifacts. Firmware-specific binaries are maintained as a set; a generic KernelSU binary is not documented as interchangeable with that set.

Publication builds use one source revision and abort if the base branch advances before publication. Metadata and checksums are refreshed together, while historical artifact paths remain separate for older clients.

The earlier CZG3 profile has an automated KernelSU build configuration. The ZZI4 KernelSU pair is maintained separately and is deliberately excluded from generic rebuilding. Automated payload publication does not establish reproducibility of that pair.

This repository supplies the files and metadata. App release signing, interface behavior, recovery controls and user-facing logs are maintained in the companion app.

## Credits and license

- [BuSung-dev/Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads): original payload structure, build tooling and Samsung integration.
- [BuSung-dev/Root-My-Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy): original companion application.
- [mitschud](https://github.com/mitschud): later Galaxy S25 firmware contributions adapted by this fork.
- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia): published exploit lineage.
- [KernelSU](https://github.com/tiann/KernelSU), by tiann and contributors: root framework and userspace lifecycle.
- [HyperRamzey/Root-My-Galaxy](https://github.com/HyperRamzey/Root-My-Galaxy): companion app automation references.

Distributed under [LICENSE](LICENSE). Derived components retain their own licenses and copyright notices.
