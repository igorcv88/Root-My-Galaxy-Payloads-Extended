# CZG3 v0266 scope

This generation deliberately changes only two runtime boundaries relative to the restored v0265 baseline:

1. App payload KASLR slide discovery prefers the existing tracefs route with the CZG3-specific `workqueue_execute_start` event id `109`. The original physical/P0 oracle code remains compiled as the fallback path.
2. The root helper attempts KernelSU late-load immediately from the UMH root window using the persisted `/data/local/tmp/ksud-s25u-kdp` copy and `--allow-shell`. If that copy is unavailable or the automatic path does not become active, the app retains the historical helper client `--late-load` fallback after bootstrap root.

The exploit race itself is intentionally not re-instrumented. No CZG3 diagnostic observer, pselect state gate, SIGRETURN gate, global syscall wrapper, keeper guard, or race telemetry source is linked by this generation.

## Artifact coupling

The v3 feed publishes the v0266 exploit together with `cve-2026-43499-root` and records the helper as `rootHelper` metadata (URL, size, SHA-256). Root My Galaxy release builds pin the payload repository commit, verify that metadata, and embed the matching helper as `libcve43499root.so`.

The legacy v2 artifact remains immutable.
