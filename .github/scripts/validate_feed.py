#!/usr/bin/env python3
import hashlib
import json
import pathlib
import re
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[2]
PREFIX = (
    "https://raw.githubusercontent.com/igorcv88/"
    "Root-My-Galaxy-Payloads-S938B/main/"
)
LEGACY_EXPLOIT = pathlib.Path(
    "artifacts/pa3q-S938BXXSBCZG3/cve-2026-43499-app.so"
)
V0265_EXPLOIT = pathlib.Path(
    "artifacts/pa3q-S938BXXSBCZG3-v0265/cve-2026-43499-app.so"
)
V0266_DIR = pathlib.Path("artifacts/pa3q-S938BXXSBCZG3-v0266")
LEGACY_EXPLOIT_SHA256 = (
    "ba0894d1214e3c46305d8acb0ab065eb110833b4b9973c9250aca5bfcb98c214"
)
V0265_EXPLOIT_SHA256 = (
    "1719e9362cd19e58521cb785fcaa40c4613ca854d0c3c9fb8320edf8e9046303"
)
EXPECTED_IDENTITY = {
    "manufacturer": "samsung",
    "model": "SM-S938B",
    "device": "pa3q",
    "buildDisplay": "BP4A.251205.006.S938BXXSBCZG3",
    "buildFingerprint": (
        "samsung/pa3qxxx/pa3q:16/BP4A.251205.006/"
        "S938BXXSBCZG3_OXMBCZG3:user/release-keys"
    ),
    "kernelRelease": "6.6.98-android15-8-pd6ff1cd-abogkiS938BXXSBCZG3-4k",
    "kernelVersionInfo": "#1 SMP PREEMPT Thu Jul  2 00:48:56 UTC 2026",
    "machine": "aarch64",
    "sdk": 36,
    "abi": "arm64-v8a",
    "pageSize": 4096,
}


def local_path(url: str) -> pathlib.Path:
    if not url.startswith(PREFIX):
        raise AssertionError(f"external artifact URL: {url}")
    return ROOT / urllib.parse.unquote(url.removeprefix(PREFIX))


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_v3_artifact(artifact: dict, label: str) -> pathlib.Path:
    expected_sha = artifact["sha256"].lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise AssertionError(f"invalid SHA-256 in CZG3 v3 {label} entry")
    path = local_path(artifact["url"])
    if not path.is_file():
        raise AssertionError(f"missing {path.relative_to(ROOT)}")
    if path.stat().st_size != artifact["size"]:
        raise AssertionError(f"size mismatch for {path.relative_to(ROOT)}")
    if sha256(path) != expected_sha:
        raise AssertionError(f"SHA-256 mismatch for {path.relative_to(ROOT)}")
    return path


def validate_v0266(target: dict, exploit: pathlib.Path) -> None:
    expected_exploit = ROOT / V0266_DIR / "cve-2026-43499-app.so"
    if exploit != expected_exploit:
        raise AssertionError("v0266 exploit path is not canonical")
    if exploit.stat().st_size != 104128:
        raise AssertionError("v0266 exploit must remain the fixed 104128-byte release")

    helper = target.get("rootHelper")
    if not isinstance(helper, dict):
        raise AssertionError("v0266 requires rootHelper metadata")
    helper_path = validate_v3_artifact(helper, "rootHelper")
    expected_helper = ROOT / V0266_DIR / "cve-2026-43499-root"
    if helper_path != expected_helper:
        raise AssertionError("v0266 root helper path is not canonical")

    sha_file = ROOT / V0266_DIR / "cve-2026-43499-root.sha256"
    if not sha_file.is_file():
        raise AssertionError("v0266 root helper checksum sidecar is missing")
    expected_line = f"{helper['sha256'].lower()}  cve-2026-43499-root\n"
    if sha_file.read_text(encoding="utf-8") != expected_line:
        raise AssertionError("v0266 root helper checksum sidecar drifted")


def main() -> None:
    v2 = json.loads((ROOT / "support/targets-v2.json").read_text(encoding="utf-8"))
    assert v2.get("schemaVersion") == 2
    assert len(v2.get("targets", [])) == 1, "legacy v2 feed must remain S938B-only"
    legacy = v2["targets"][0]
    assert legacy["profileId"] == "pa3q-S938BXXSBCZG3"
    assert legacy["manufacturer"] == EXPECTED_IDENTITY["manufacturer"]
    assert legacy["model"] == EXPECTED_IDENTITY["model"]
    assert legacy["device"] == EXPECTED_IDENTITY["device"]
    assert legacy["buildDisplay"] == EXPECTED_IDENTITY["buildDisplay"]
    assert legacy["buildFingerprint"] == EXPECTED_IDENTITY["buildFingerprint"]
    assert legacy["kernelRelease"] == EXPECTED_IDENTITY["kernelRelease"]
    assert legacy["kernelBuildVersion"] == EXPECTED_IDENTITY["kernelVersionInfo"]
    assert legacy["sdk"] == EXPECTED_IDENTITY["sdk"]
    assert legacy["abi"] == EXPECTED_IDENTITY["abi"]
    assert legacy["pageSize"] == EXPECTED_IDENTITY["pageSize"]

    legacy_exploit = local_path(legacy["exploit"]["url"])
    assert legacy_exploit == ROOT / LEGACY_EXPLOIT
    assert legacy_exploit.stat().st_size == legacy["exploit"]["size"] == 104128
    assert sha256(legacy_exploit) == LEGACY_EXPLOIT_SHA256, (
        "legacy hardware-validated v2 exploit changed"
    )
    legacy_ksud = local_path(legacy["kernelsu"]["url"])
    assert legacy_ksud.is_file()
    assert legacy_ksud.stat().st_size == legacy["kernelsu"]["size"] == 6407096

    v3 = json.loads((ROOT / "support/targets-v3.json").read_text(encoding="utf-8"))
    assert v3.get("schemaVersion") == 3
    payloads = v3.get("payloads")
    assert isinstance(payloads, list) and len(payloads) == 1, "v3 feed must remain S938B-only"
    target = payloads[0]
    assert target["payloadId"] == "pa3q-S938BXXSBCZG3"
    assert target["models"] == ["SM-S938B"]
    assert target["kernelVersions"] == ["6.6.98"]
    assert target["exactMatch"] == EXPECTED_IDENTITY, "exact S938B identity drifted"

    exploit = validate_v3_artifact(target["exploit"], "exploit")
    # KernelSU is intentionally rebuildable from the exact KSU_TAG_SHA plus the
    # versioned Samsung/RMG patches in the canonical workflow. Validate the
    # published artifact against its feed size/SHA instead of pinning a stale
    # binary digest here; otherwise every legitimate patched ksud rebuild is
    # rejected after the workflow has correctly updated the manifest.
    validate_v3_artifact(target["kernelsu"], "kernelsu")

    if exploit == ROOT / V0265_EXPLOIT:
        assert target["exploit"]["sha256"] == V0265_EXPLOIT_SHA256
        assert exploit.read_bytes() != legacy_exploit.read_bytes(), (
            "v2 legacy and v3 restored payloads unexpectedly collapsed"
        )
        print("Payload feed is valid (immutable legacy v2 + restored v0265 v3 CZG3)")
    elif V0266_DIR in exploit.relative_to(ROOT).parents:
        validate_v0266(target, exploit)
        print("Payload feed is valid (immutable legacy v2 + tracefs/auto-late-load v0266 CZG3)")
    else:
        raise AssertionError(f"unexpected CZG3 v3 exploit path: {exploit.relative_to(ROOT)}")

    assert (ROOT / "src/targets/pa3q-S938BXXSBCZG3/target.h").is_file()
    assert (ROOT / "src/targets/pa3q-S938BXXSBCZG3/p0_fingerprint.h").is_file()


if __name__ == "__main__":
    main()
