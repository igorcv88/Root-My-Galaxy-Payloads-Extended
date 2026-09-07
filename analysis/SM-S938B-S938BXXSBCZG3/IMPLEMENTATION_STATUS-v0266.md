# Implementation status

Implemented in source/workflow:

- CZG3 tracefs app-payload flags with event id 109;
- root helper auto-late-load using the persisted ksud and `--allow-shell`;
- `--ksu-info` verification command;
- client late-load fallback retained;
- v0266 exploit/root-helper joint build and publication;
- v3 `rootHelper` URL/size/SHA-256 metadata;
- transitional validator accepting current v0265 before publication and enforcing v0266 coupling after publication;
- immutable legacy v2 checks preserved.

Pending validation:

- NDK build through **Atualizar Payloads → Exploit** after merge;
- generated artifact/helper hashes;
- real-device sentinel runs.
