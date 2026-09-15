#!/usr/bin/env python3
import hashlib
import json
import pathlib
import re
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[2]
PREFIX = "https://raw.githubusercontent.com/igorcv88/Root-My-Galaxy-Payloads-Extended/main/"

EXPECTED_EXACT = {
    "pa3q-S938BXXSBCZG3": {
        "manufacturer": "samsung",
        "model": "SM-S938B",
        "device": "pa3q",
        "buildDisplay": "BP4A.251205.006.S938BXXSBCZG3",
        "buildFingerprint": "samsung/pa3qxxx/pa3q:16/BP4A.251205.006/S938BXXSBCZG3_OXMBCZG3:user/release-keys",
        "kernelRelease": "6.6.98-android15-8-pd6ff1cd-abogkiS938BXXSBCZG3-4k",
        "kernelVersionInfo": "#1 SMP PREEMPT Thu Jul  2 00:48:56 UTC 2026",
        "machine": "aarch64",
        "sdk": 36,
        "abi": "arm64-v8a",
        "pageSize": 4096,
    },
    "pa3q-S938BXXUCZZI4": {
        "manufacturer": "samsung",
        "model": "SM-S938B",
        "device": "pa3q",
        "buildDisplay": "CP2A.260605.016.S938BXXUCZZI4",
        "buildFingerprint": "samsung/pa3qxxx/pa3q:17/CP2A.260605.016/S938BXXUCZZI4_OXMCZZI4:user/release-keys",
        "kernelRelease": "6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZI4-4k",
        "kernelVersionInfo": "#1 SMP PREEMPT Wed Sep  2 08:13:43 UTC 2026",
        "machine": "aarch64",
        "sdk": 37,
        "abi": "arm64-v8a",
        "pageSize": 4096,
    },
    "pa1q-S931BXXUCZZI4": {
        "manufacturer": "samsung",
        "model": "SM-S931B",
        "device": "pa1q",
        "buildDisplay": "CP2A.260605.016.S931BXXUCZZI4",
        "buildFingerprint": "samsung/pa1qxeea/pa1q:17/CP2A.260605.016/S931BXXUCZZI4_OXMCZZI4:user/release-keys",
        "kernelRelease": "6.6.127-android15-8-p33f4ffe-abogkiS931BXXUCZZI4-4k",
        "kernelVersionInfo": "#1 SMP PREEMPT Wed Sep  2 08:11:10 UTC 2026",
        "machine": "aarch64",
        "sdk": 37,
        "abi": "arm64-v8a",
        "pageSize": 4096,
    },
}

EXPECTED_PATHS = {
    "pa3q-S938BXXSBCZG3": {
        "exploit": "artifacts/pa3q-S938BXXSBCZG3-v0266/cve-2026-43499-app.so",
        "kernelsu": "kernelsu/ksud-s25u-kdp-v3.3.0",
        "rootHelper": "artifacts/pa3q-S938BXXSBCZG3-v0266/cve-2026-43499-root",
    },
    "pa3q-S938BXXUCZZI4": {
        "exploit": "artifacts/pa3q-S938BXXUCZZI4-v0300/cve-2026-43499-app.so",
        "kernelsu": "kernelsu/ksud-pa3q-S938BXXUCZZI4-kdp-v3.3.0",
        "rootHelper": "artifacts/pa3q-S938BXXUCZZI4-v0300/cve-2026-43499-root",
    },
    "pa1q-S931BXXUCZZI4": {
        "exploit": "artifacts/pa1q-S931BXXUCZZI4/cve-2026-43499-app.so",
        "kernelsu": "kernelsu/ksud-pa1q-S931BXXUCZZI4-kdp",
        "rootHelper": "artifacts/pa3q-S938BXXUCZZI4-v0300/cve-2026-43499-root",
    },
    "galaxy-s25-series-2026-06-07": {
        "exploit": "artifacts/pa3q-S938NKSUACZF1/cve-2026-43499-app.so",
        "kernelsu": "kernelsu/ksud-s25u-kdp",
    },
}

EXPECTED_POLICIES = {
    "pa3q-S938BXXSBCZG3": ("default", False),
    "pa3q-S938BXXUCZZI4": ("auto", True),
    "pa1q-S931BXXUCZZI4": ("default", True),
    "galaxy-s25-series-2026-06-07": ("default", False),
}

STABLE_ROOT_HELPER_SHA256 = "788611baf566f0ca9008d28fa7d1b1edb4657efc56e4b5ac24b319ae12519dd4"


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def local_path(url: str) -> pathlib.Path:
    if not url.startswith(PREFIX):
        raise AssertionError(f"artifact must come from the production payload repository: {url}")
    relative = urllib.parse.unquote(url.removeprefix(PREFIX))
    path = (ROOT / relative).resolve()
    if ROOT.resolve() not in path.parents:
        raise AssertionError(f"artifact path escapes repository: {url}")
    return path


def validate_artifact(artifact: dict, label: str, expected_path: str) -> pathlib.Path:
    if not isinstance(artifact, dict):
        raise AssertionError(f"missing {label} metadata")
    digest = str(artifact.get("sha256", "")).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise AssertionError(f"invalid SHA-256 for {label}")
    path = local_path(str(artifact.get("url", "")))
    expected = ROOT / expected_path
    if path != expected.resolve():
        raise AssertionError(f"unexpected path for {label}: {path.relative_to(ROOT)}")
    if not path.is_file():
        raise AssertionError(f"missing artifact: {path.relative_to(ROOT)}")
    if path.stat().st_size != int(artifact.get("size", -1)):
        raise AssertionError(f"size mismatch for {label}")
    if sha256(path) != digest:
        raise AssertionError(f"SHA-256 mismatch for {label}")
    return path


def validate_route_policy(target: dict) -> None:
    payload_id = target["payloadId"]
    route, shell = EXPECTED_POLICIES[payload_id]
    expected = {
        "slideRoute": route,
        "attempts": 24,
        "attemptTimeoutSec": 120,
        "p0AttemptTimeoutSec": 45,
        "p0OffsetCache": True,
        "prefersShellTransport": shell,
    }
    if target.get("routePolicy") != expected:
        raise AssertionError(f"route policy drifted for {payload_id}")


def validate_v2() -> None:
    manifest = json.loads((ROOT / "support/targets-v2.json").read_text(encoding="utf-8"))
    if manifest.get("schemaVersion") != 2:
        raise AssertionError("legacy feed must remain schema v2")
    targets = manifest.get("targets", [])
    if len(targets) != 1 or targets[0].get("profileId") != "pa3q-S938BXXSBCZG3":
        raise AssertionError("legacy v2 feed must remain the CZG3 compatibility profile")
    for key in ("exploit", "kernelsu"):
        artifact = targets[0][key]
        path = local_path(artifact["url"])
        if not path.is_file() or path.stat().st_size != artifact["size"]:
            raise AssertionError(f"invalid v2 {key} artifact")


def validate_v3() -> None:
    manifest = json.loads((ROOT / "support/targets-v3.json").read_text(encoding="utf-8"))
    if manifest.get("schemaVersion") != 3:
        raise AssertionError("production feed must use schema v3")
    payloads = manifest.get("payloads")
    if not isinstance(payloads, list):
        raise AssertionError("v3 payloads must be a list")

    by_id = {target.get("payloadId"): target for target in payloads}
    expected_ids = set(EXPECTED_PATHS)
    if len(by_id) != len(payloads) or set(by_id) != expected_ids:
        raise AssertionError(f"unexpected v3 target set: {sorted(by_id)}")

    for payload_id, target in by_id.items():
        if not target.get("models") or not target.get("kernelVersions"):
            raise AssertionError(f"missing compatibility metadata for {payload_id}")
        paths = EXPECTED_PATHS[payload_id]
        validate_artifact(target["exploit"], f"{payload_id} exploit", paths["exploit"])
        validate_artifact(target["kernelsu"], f"{payload_id} KernelSU", paths["kernelsu"])
        validate_route_policy(target)

        helper_path = paths.get("rootHelper")
        if helper_path:
            helper = target.get("rootHelper")
            validate_artifact(helper, f"{payload_id} root helper", helper_path)
            if helper["sha256"].lower() != STABLE_ROOT_HELPER_SHA256 or helper["size"] != 31496:
                raise AssertionError(f"root helper contract drifted for {payload_id}")
        elif "rootHelper" in target:
            raise AssertionError(f"manual generic profile must not add an exact root-helper contract: {payload_id}")

        if payload_id in EXPECTED_EXACT:
            if target.get("exactMatch") != EXPECTED_EXACT[payload_id]:
                raise AssertionError(f"exact identity drifted for {payload_id}")
        elif "exactMatch" in target:
            raise AssertionError(f"generic Advanced profile must remain non-exact: {payload_id}")

    generic = by_id["galaxy-s25-series-2026-06-07"]
    if generic["models"] != ["SM-S931B", "SM-S936B"] or generic["kernelVersions"] != ["6.6.98"]:
        raise AssertionError("generic S25/S25+ Advanced profile compatibility drifted")

    print(
        "Payload feed is valid: exact S938B CZG3/ZZI4, exact S931B ZZI4, "
        "and Advanced-only S931B/S936B 6.6.98"
    )


def main() -> None:
    validate_v2()
    validate_v3()


if __name__ == "__main__":
    main()
