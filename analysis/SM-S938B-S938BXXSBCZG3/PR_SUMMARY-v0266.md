# PR summary

This branch introduces the deliberately narrow CZG3 v0266 generation: tracefs slide discovery using event id 109 with the existing P0 path retained as fallback, plus the hardware-tested root-helper auto-late-load route using KernelSU `--allow-shell`.

The exploit race remains free of the diagnostic observer, state gates, syscall wrappers, keeper guard, and race telemetry removed by the restored baseline.

The payload workflow builds/publishes the v0266 exploit and matching root helper together and records helper URL/size/SHA-256 as `rootHelper` in the v3 feed. Legacy v2 remains immutable. v0265 remains validator-compatible until the v0266 workflow is actually run after merge.

No NDK build or integrated real-device v0266 run has been executed in this conversation environment yet.
