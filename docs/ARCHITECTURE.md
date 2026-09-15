# Production architecture notes

This document records the current production relationships between the target feed, exploit payload, root helper and KernelSU artifacts.

## Feed contract

The companion app resolves targets from `support/targets-v3.json`. Exact profiles bind a model to its build display, fingerprint, kernel release/version, architecture, SDK, ABI and page size.

Each profile supplies the exploit, KernelSU and root-helper metadata plus its route policy. Firmware behavior therefore stays with the target data rather than being shared implicitly across devices.

## Current target families

CZG3 on S938B remains the Android 16 / kernel 6.6.98 profile.

ZZI4 is an Android 17 / kernel 6.6.127 family. S938B and S931B have separate exact identities and target artifacts. S936B requires its real device identity before an exact profile is published.

## ZZI4 exploit behavior

The validated S938B ZZI4 route can obtain the KASLR slide from Tracefs while addressing kernel data through the physical-load alias. The payload retains the physical P0 oracle and bounded FOPS retries.

Target constants, offsets and build-specific switches live under the target source tree. Changes to another firmware should not be inferred from the ZZI4 S938B values.

## Root helper

After bootstrap UID 0, the root helper can start the KernelSU handoff directly. The current Samsung path stages the verified daemon before the security transition and uses a DEFEX-compatible execution bind over `/system/bin/logcat`.

The helper then starts `ksud late-load --allow-shell`. The app also retains a serialized late-load fallback for cases where auto-late-load does not reach global readiness.

## KernelSU staged-daemon path

The One UI 9 KernelSU build serializes late-load callers with an abstract AF_UNIX lock, uses the kernel boot ID to suppress same-boot lifecycle replay, and switches into PID1's mount namespace before taking ownership of module/systemless mounts.

The staged daemon is installed from the verified pre-uploaded file rather than reopened from the bootstrap executable. Readiness is published only after the blocking mount stages complete.

These behaviors belong to the KernelSU artifact. App-side post-root code should leave daemon installation and late-load ownership to KernelSU.

## Build policy

Firmware-specific KernelSU pairs can be marked as preserved artifacts when they cannot be reproduced safely by the generic build job. The ZZI4 pair currently follows this model.

The publication workflow pins one source commit for a build and verifies that `main` has not moved before publishing. Artifact metadata and hashes are updated together with the target feed.
