# v0266 rollout order

1. Merge the payload source/workflow changes.
2. Run **Atualizar Payloads** on `main` with **Exploit**. This generates and publishes the v0266 exploit plus the matching root helper and `rootHelper` metadata. KernelSU does not need to be rebuilt for this step.
3. Verify `support/targets-v3.json` points to `artifacts/pa3q-S938BXXSBCZG3-v0266/` for the exploit and root helper and that `.github/scripts/validate_feed.py` passes in the workflow.
4. Merge the companion application change.
5. Generate the application release. Its release workflow resolves the payload `main` commit, verifies the published helper size/SHA-256, and embeds that exact helper into the APK before Gradle build/signing.

Do not publish an application release that advertises a v0266 feed while embedding an older helper. Runtime feed/helper verification is intentionally fail-closed.
