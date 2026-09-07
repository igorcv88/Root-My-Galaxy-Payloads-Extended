# v0266 validation status

- The source branch has not been built in this conversation environment; the NDK build and artifact SHA-256 values will be produced by the existing **Atualizar Payloads** workflow after merge.
- The v0266 workflow is fail-closed for exploit size, expected build label, forbidden diagnostic markers, root-helper feature strings, artifact size/SHA-256, and feed consistency.
- Tracefs event id `109` and the auto-late-load helper behavior are based on the CZG3 analysis/device-tested upstream work, but this exact integrated v0266 generation still requires a real-device run before it should be treated as the new known-good baseline.
- The legacy v2 artifact remains immutable, and the current v0265 v3 artifact remains accepted by the validator until v0266 is actually generated and published.
