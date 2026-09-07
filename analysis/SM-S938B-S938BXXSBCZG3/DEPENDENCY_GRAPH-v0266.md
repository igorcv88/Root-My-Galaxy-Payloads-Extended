# Dependency boundary

The v0266 exploit artifact invokes the APK-provided root helper through `CVE43499_ROOT_HELPER`. The helper may consume a persisted `/data/local/tmp/ksud-s25u-kdp` to auto-late-load KernelSU while root is available. If that persisted loader is absent or the automatic path does not become active, the app stages its verified ksud after bootstrap and invokes the helper's client late-load fallback.

The v3 feed therefore couples v0266 to the matching helper by URL, size, and SHA-256. KernelSU remains a separately verified artifact in the same target entry.
