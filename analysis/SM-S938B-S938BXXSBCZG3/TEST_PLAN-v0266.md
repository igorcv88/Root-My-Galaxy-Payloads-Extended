# Minimal v0266 hardware validation

The first v0266 validation should avoid a timing sweep.

1. Generate/publish v0266 using **Atualizar Payloads → Exploit** and record the produced exploit/helper SHA-256 values.
2. Use the companion application build containing the exact published `rootHelper`.
3. Start with the existing configured CZG3 launch uptime; do not change attempts, FOPS timing, or diagnostic instrumentation.
4. Run one Manual Online sentinel. Confirm normal exploit success markers and KernelSU verification.
5. If successful, create/confirm the offline cache and run one full reboot Auto Root sentinel.
6. Check whether the Auto Root history reports `KernelSU auto-late-load verified` or the client late-load fallback. Either is valid; the important requirement is that root acquisition remains standalone/offline and succeeds.
7. Only after those sentinels pass should post-root Wireless ADB/Shizuku/userspace restart be enabled and tested.

A tracefs failure that falls back to the existing P0 route is not by itself a v0266 failure. A regression is failure of the exploit/root path compared with the restored baseline under otherwise identical settings.
