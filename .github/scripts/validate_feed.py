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
ZZI4_DIR = pathlib.Path("artifacts/pa3q-S938BXXUCZZI4-v0300")
ZZI4_KSUD = pathlib.Path("kernelsu/ksud-pa3q-S938BXXUCZZI4-kdp-v3.3.0")
S931B_ZZI4_EXPLOIT = pathlib.Path(
    "artifacts/pa1q-S931BXXUCZZI4/cve-2026-43499-app.so"
)
S931B_ZZI4_KSUD = pathlib.Path("kernelsu/ksud-pa1q-S931BXXUCZZI4-kdp")
GENERIC_S25_EXPLOIT = pathlib.Path(
    "artifacts/pa3q-S938NKSUACZF1/cve-2026-43499-app.so"
)
GENERIC_S25_KSUD = pathlib.Path("kernelsu/ksud-s25u-kdp")
GENERIC_S25_EXPLOIT_SHA256 = (
    "6311e5ae1a381fd96b8a989e82525521ed9b00cff4e0d3020d3904eb5716587c"
)
GENERIC_S25_KSUD_SHA256 = (
    "fa3edcc7d168637394877b30cb1f909d762dda788ec14051f4ae79edd6562d63"
)
S931B_ZZI4_EXPLOIT_SHA256 = (
    "2f9799912ec6c297d9190bc2b82ff417ff451854a08e9524fa549743470284af"
)
S931B_ZZI4_KSUD_SHA256 = (
    "1e1cb6b861d0d4951b7374c12404eee1fb4c02a77240e0500ca571a302396374"
)
LEGACY_EXPLOIT_SHA256 = (
    "ba0894d1214e3c46305d8acb0ab065eb110833b4b9973c9250aca5bfcb98c214"
)
V0265_EXPLOIT_SHA256 = (
    "1719e9362cd19e58521cb785fcaa40c4613ca854d0c3c9fb8320edf8e9046303"
)
STABLE_ROOT_HELPER_SHA256 = (
    "788611baf566f0ca9008d28fa7d1b1edb4657efc56e4b5ac24b319ae12519dd4"
)
EXPECTED_CZG3_IDENTITY = {
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
EXPECTED_ZZI4_IDENTITY = {
    "manufacturer": "samsung",
    "model": "SM-S938B",
    "device": "pa3q",
    "buildDisplay": "CP2A.260605.016.S938BXXUCZZI4",
    "buildFingerprint": (
        "samsung/pa3qxxx/pa3q:17/CP2A.260605.016/"
        "S938BXXUCZZI4_OXMCZZI4:user/release-keys"
    ),
    "kernelRelease": "6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZI4-4k",
    "kernelVersionInfo": "#1 SMP PREEMPT Wed Sep  2 08:13:43 UTC 2026",
    "machine": "aarch64",
    "sdk": 37,
    "abi": "arm64-v8a",
    "pageSize": 4096,
}
EXPECTED_S931B_ZZI4_IDENTITY = {
    "manufacturer": "samsung",
    "model": "SM-S931B",
    "device": "pa1q",
    "buildDisplay": "CP2A.260605.016.S931BXXUCZZI4",
    "buildFingerprint": (
        "samsung/pa1qxeea/pa1q:17/CP2A.260605.016/"
        "S931BXXUCZZI4_OXMCZZI4:user/release-keys"
    ),
    "kernelRelease": "6.6.127-android15-8-p33f4ffe-abogkiS931BXXUCZZI4-4k",
    "kernelVersionInfo": "#1 SMP PREEMPT Wed Sep  2 08:11:10 UTC 2026",
    "machine": "aarch64",
    "sdk": 37,
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
        raise AssertionError(f"invalid SHA-256 in v3 {label} entry")
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
    helper_path = validate_v3_artifact(helper, "CZG3 rootHelper")
    expected_helper = ROOT / V0266_DIR / "cve-2026-43499-root"
    if helper_path != expected_helper:
        raise AssertionError("v0266 root helper path is not canonical")

    sha_file = ROOT / V0266_DIR / "cve-2026-43499-root.sha256"
    if not sha_file.is_file():
        raise AssertionError("v0266 root helper checksum sidecar is missing")
    expected_line = f"{helper['sha256'].lower()}  cve-2026-43499-root\n"
    if sha_file.read_text(encoding="utf-8") != expected_line:
        raise AssertionError("v0266 root helper checksum sidecar drifted")


def validate_zzi4(target: dict) -> None:
    assert target["payloadId"] == "pa3q-S938BXXUCZZI4"
    assert target["models"] == ["SM-S938B"]
    assert target["kernelVersions"] == ["6.6.127"]
    assert target["exactMatch"] == EXPECTED_ZZI4_IDENTITY, "exact ZZI4 identity drifted"

    exploit = validate_v3_artifact(target["exploit"], "ZZI4 exploit")
    expected_exploit = ROOT / ZZI4_DIR / "cve-2026-43499-app.so"
    assert exploit == expected_exploit, "ZZI4 exploit path is not canonical"
    assert exploit.stat().st_size == 104128

    helper = validate_v3_artifact(target["rootHelper"], "ZZI4 rootHelper")
    assert helper == ROOT / ZZI4_DIR / "cve-2026-43499-root"

    ksud = validate_v3_artifact(target["kernelsu"], "ZZI4 KernelSU")
    assert ksud == ROOT / ZZI4_KSUD

    sums = ROOT / ZZI4_DIR / "SHA256SUMS"
    assert sums.is_file(), "ZZI4 SHA256SUMS missing"
    sums_text = sums.read_text(encoding="utf-8")
    assert target["exploit"]["sha256"] in sums_text
    assert target["rootHelper"]["sha256"] in sums_text
    assert target["kernelsu"]["sha256"] in sums_text

    assert (ROOT / "src/targets/pa3q-S938BXXUCZZI4/target.h").is_file()
    assert (ROOT / "src/targets/pa3q-S938BXXUCZZI4/p0_fingerprint.h").is_file()


def validate_s931b_zzi4(target: dict) -> None:
    assert target["payloadId"] == "pa1q-S931BXXUCZZI4"
    assert target["models"] == ["SM-S931B"]
    assert target["kernelVersions"] == ["6.6.127"]
    assert target["exactMatch"] == EXPECTED_S931B_ZZI4_IDENTITY, (
        "exact S931B ZZI4 identity drifted"
    )

    exploit = validate_v3_artifact(target["exploit"], "S931B ZZI4 exploit")
    assert exploit == ROOT / S931B_ZZI4_EXPLOIT
    assert exploit.stat().st_size == 104128
    assert target["exploit"]["sha256"] == S931B_ZZI4_EXPLOIT_SHA256

    ksud = validate_v3_artifact(target["kernelsu"], "S931B ZZI4 KernelSU")
    assert ksud == ROOT / S931B_ZZI4_KSUD
    assert ksud.stat().st_size == 6419120
    assert target["kernelsu"]["sha256"] == S931B_ZZI4_KSUD_SHA256
    assert target["kernelsu"].get("kmi") == "android15-6.6"

    helper = validate_v3_artifact(target["rootHelper"], "S931B stable rootHelper")
    assert helper == ROOT / ZZI4_DIR / "cve-2026-43499-root"
    assert helper.stat().st_size == 31496
    assert target["rootHelper"]["sha256"] == STABLE_ROOT_HELPER_SHA256

    assert target.get("routePolicy") == {
        "slideRoute": "default",
        "attempts": 24,
        "attemptTimeoutSec": 120,
        "p0AttemptTimeoutSec": 45,
        "p0OffsetCache": True,
        "prefersShellTransport": True,
    }, "S931B ZZI4 route policy drifted"


def validate_generic_s25_b(target: dict) -> None:
    assert target["payloadId"] == "galaxy-s25-series-2026-06-07"
    assert target["models"] == ["SM-S931B", "SM-S936B"]
    assert target["kernelVersions"] == ["6.6.98"]
    assert "exactMatch" not in target, (
        "generic S931B/S936B 6.6.98 profile must remain manual/Advanced-only; "
        "exact firmware identities belong in separate profiles"
    )
    assert "rootHelper" not in target, (
        "generic S931B/S936B profile must not impose a target-specific "
        "root-helper contract"
    )

    exploit = validate_v3_artifact(target["exploit"], "generic S25 B-series exploit")
    assert exploit == ROOT / GENERIC_S25_EXPLOIT
    assert exploit.stat().st_size == 104128
    assert target["exploit"]["sha256"] == GENERIC_S25_EXPLOIT_SHA256

    ksud = validate_v3_artifact(target["kernelsu"], "generic S25 B-series KernelSU")
    assert ksud == ROOT / GENERIC_S25_KSUD
    assert ksud.stat().st_size == 6407096
    assert target["kernelsu"]["sha256"] == GENERIC_S25_KSUD_SHA256
    assert target["kernelsu"].get("kmi") == "android15-6.6"

    policy = target.get("routePolicy")
    assert policy == {
        "slideRoute": "default",
        "attempts": 24,
        "attemptTimeoutSec": 120,
        "p0AttemptTimeoutSec": 45,
        "p0OffsetCache": True,
        "prefersShellTransport": False,
    }, "generic S25 B-series route policy drifted"

    assert (ROOT / "src/targets/pa3q-S938NKSUACZF1/target.h").is_file()
    assert (ROOT / "src/targets/pa3q-S938NKSUACZF1/p0_fingerprint.h").is_file()


def main() -> None:
    v2 = json.loads((ROOT / "support/targets-v2.json").read_text(encoding="utf-8"))
    assert v2.get("schemaVersion") == 2
    assert len(v2.get("targets", [])) == 1, "legacy v2 feed must remain CZG3-only"
    legacy = v2["targets"][0]
    assert legacy["profileId"] == "pa3q-S938BXXSBCZG3"
    assert legacy["manufacturer"] == EXPECTED_CZG3_IDENTITY["manufacturer"]
    assert legacy["model"] == EXPECTED_CZG3_IDENTITY["model"]
    assert legacy["device"] == EXPECTED_CZG3_IDENTITY["device"]
    assert legacy["buildDisplay"] == EXPECTED_CZG3_IDENTITY["buildDisplay"]
    assert legacy["buildFingerprint"] == EXPECTED_CZG3_IDENTITY["buildFingerprint"]
    assert legacy["kernelRelease"] == EXPECTED_CZG3_IDENTITY["kernelRelease"]
    assert legacy["kernelBuildVersion"] == EXPECTED_CZG3_IDENTITY["kernelVersionInfo"]
    assert legacy["sdk"] == EXPECTED_CZG3_IDENTITY["sdk"]
    assert legacy["abi"] == EXPECTED_CZG3_IDENTITY["abi"]
    assert legacy["pageSize"] == EXPECTED_CZG3_IDENTITY["pageSize"]

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
    assert isinstance(payloads, list) and len(payloads) == 4, (
        "v3 feed must contain exact S938B CZG3/ZZI4, exact S931B ZZI4, "
        "and the manual S931B/S936B 6.6.98 profile"
    )
    by_id = {item["payloadId"]: item for item in payloads}
    assert set(by_id) == {
        "pa3q-S938BXXSBCZG3",
        "pa3q-S938BXXUCZZI4",
        "pa1q-S931BXXUCZZI4",
        "galaxy-s25-series-2026-06-07",
    }

    target = by_id["pa3q-S938BXXSBCZG3"]
    assert target["models"] == ["SM-S938B"]
    assert target["kernelVersions"] == ["6.6.98"]
    assert target["exactMatch"] == EXPECTED_CZG3_IDENTITY, "exact CZG3 identity drifted"

    exploit = validate_v3_artifact(target["exploit"], "CZG3 exploit")
    validate_v3_artifact(target["kernelsu"], "CZG3 KernelSU")

    if exploit == ROOT / V0265_EXPLOIT:
        assert target["exploit"]["sha256"] == V0265_EXPLOIT_SHA256
        assert exploit.read_bytes() != legacy_exploit.read_bytes(), (
            "v2 legacy and v3 restored payloads unexpectedly collapsed"
        )
    elif V0266_DIR in exploit.relative_to(ROOT).parents:
        validate_v0266(target, exploit)
    else:
        raise AssertionError(f"unexpected CZG3 v3 exploit path: {exploit.relative_to(ROOT)}")

    assert (ROOT / "src/targets/pa3q-S938BXXSBCZG3/target.h").is_file()
    assert (ROOT / "src/targets/pa3q-S938BXXSBCZG3/p0_fingerprint.h").is_file()

    validate_zzi4(by_id["pa3q-S938BXXUCZZI4"])
    validate_s931b_zzi4(by_id["pa1q-S931BXXUCZZI4"])
    validate_generic_s25_b(by_id["galaxy-s25-series-2026-06-07"])
    print(
        "Payload feed is valid "
        "(exact S938B CZG3/ZZI4 + exact S931B ZZI4 + "
        "manual S931B/S936B 6.6.98 profile)"
    )


if __name__ == "__main__":
    main()
