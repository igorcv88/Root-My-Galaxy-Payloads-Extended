# Support feed

The production app reads `targets-v3.json`. `targets-v2.json` is kept for older clients that still use schema v2.

## Schema v3

Each payload entry contains:

- `payloadId` and `displayName`;
- supported `models` and short `kernelVersions` for the manual/Advanced catalog;
- an optional `exactMatch` identity for automatic selection;
- exploit and KernelSU URL, size and SHA-256 metadata;
- optional `rootHelper` metadata when the profile requires an exact bundled-helper contract;
- a target-specific `routePolicy`.

`models` and `kernelVersions` make a profile visible to the manual/Advanced flow. They do not authorize automatic execution.

Automatic selection is fail-closed. A profile with `exactMatch` is selected only when the complete device identity matches, including manufacturer, model, device, build display, fingerprint, full kernel release/version, architecture, SDK, ABI and page size.

Current production coverage:

| Device / firmware | Selection |
| --- | --- |
| SM-S938B / S938BXXSBCZG3 | Exact |
| SM-S938B / S938BXXUCZZI4 | Exact |
| SM-S931B / S931BXXUCZZI4 | Exact |
| SM-S931B or SM-S936B / compatible 6.6.98 builds | Manual / Advanced, unvalidated |

SM-S936B ZZI4 will receive an exact profile after its real device build, fingerprint, kernel and ABI/page-size identity are confirmed.

## Artifact integrity

The app first resolves the current `main` commit of this repository, downloads `support/targets-v3.json` from that immutable commit, and pins every artifact URL to the same commit before download.

All v3 artifact downloads are checked against the declared byte size and SHA-256 digest. Partial or mismatched files are deleted and execution fails closed.

The production feed only references files from `igorcv88/Root-My-Galaxy-Payloads-Extended`. Publication and validation scripts enforce that repository boundary.

## Buildable and preserved targets

`.github/build-targets.json` lists targets that the generic publication workflow is allowed to rebuild. Some feed entries use validated artifacts that are intentionally preserved instead of rebuilt by generic CI.

The feed validator checks every advertised production profile, including preserved targets. A target does not need to be generically rebuildable to be present in the production feed.

## Legacy schema v2

`targets-v2.json` remains the compatibility feed for older builds and stays limited to the historical CZG3 profile. Current app releases use schema v3.
