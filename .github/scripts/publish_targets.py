#!/usr/bin/env python3
"""Copy built artifacts into the repository and update the v3 feed.

Only the targets named in TARGETS are touched. Every other feed entry - and
every other artifact directory - is left byte-identical, so a single-target
run can never disturb a validated target.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil

ROOT = pathlib.Path(__file__).resolve().parents[2]
PREFIX = (
    "https://raw.githubusercontent.com/igorcv88/"
    "Root-My-Galaxy-Payloads-S938B/main/"
)


def metadata(path: pathlib.Path) -> tuple[int, str]:
    data = path.read_bytes()
    return len(data), hashlib.sha256(data).hexdigest()


def update_kernelsu_readme(module: pathlib.Path, ksud: pathlib.Path) -> None:
    module_size, module_digest = metadata(module)
    ksud_size, ksud_digest = metadata(ksud)
    readme_path = ROOT / "kernelsu/README.md"
    readme = readme_path.read_text(encoding="utf-8")
    block = re.compile(
        re.escape(module.name) + r"\nsize: \d+\nSHA-256: [0-9a-f]{64}\n\n"
        + re.escape(ksud.name) + r"\nsize: \d+\nSHA-256: [0-9a-f]{64}"
    )
    replacement = (
        f"{module.name}\nsize: {module_size}\nSHA-256: {module_digest}\n\n"
        f"{ksud.name}\nsize: {ksud_size}\nSHA-256: {ksud_digest}"
    )
    readme, count = block.subn(replacement, readme, count=1)
    if count != 1:
        raise SystemExit(
            "Could not update KernelSU artifact metadata in kernelsu/README.md"
        )
    readme_path.write_text(readme, encoding="utf-8")


def main() -> None:
    descriptor = json.loads(
        (ROOT / ".github/build-targets.json").read_text(encoding="utf-8")
    )["targets"]
    manifest_path = ROOT / "support/targets-v3.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    by_id = {item["payloadId"]: item for item in manifest["payloads"]}

    mode = os.environ["UPDATE_MODE"]
    targets = [item for item in os.environ["TARGETS"].split(",") if item]
    dist = pathlib.Path(os.environ["DIST_DIR"])
    changed: list[str] = []

    for target_id in targets:
        entry = descriptor[target_id]
        feed = by_id[target_id]
        staged = dist / target_id

        if "Exploit" in mode:
            artifact_dir = ROOT / entry["artifactDir"]
            artifact_dir.mkdir(parents=True, exist_ok=True)
            exploit = artifact_dir / "cve-2026-43499-app.so"
            helper = artifact_dir / "cve-2026-43499-root"
            shutil.copy2(staged / "cve-2026-43499-app.release.so", exploit)
            shutil.copy2(staged / "cve-2026-43499-root", helper)

            size, digest = metadata(exploit)
            feed["exploit"] = {
                "url": PREFIX + exploit.relative_to(ROOT).as_posix(),
                "size": size,
                "sha256": digest,
            }
            helper_size, helper_digest = metadata(helper)
            feed["rootHelper"] = {
                "url": PREFIX + helper.relative_to(ROOT).as_posix(),
                "size": helper_size,
                "sha256": helper_digest,
            }
            (artifact_dir / "cve-2026-43499-root.sha256").write_text(
                f"{helper_digest}  cve-2026-43499-root\n", encoding="utf-8"
            )
            changed.append(entry["artifactDir"])
            print(f"{target_id}: exploit {size} bytes {digest}")

        kernelsu = entry.get("kernelSu")
        if "KernelSU" in mode and kernelsu and (staged / kernelsu["ksudName"]).exists():
            module = ROOT / "kernelsu" / kernelsu["moduleName"]
            ksud = ROOT / "kernelsu" / kernelsu["ksudName"]
            shutil.copy2(staged / kernelsu["moduleName"], module)
            shutil.copy2(staged / kernelsu["ksudName"], ksud)
            size, digest = metadata(ksud)
            feed["kernelsu"]["url"] = PREFIX + ksud.relative_to(ROOT).as_posix()
            feed["kernelsu"]["size"] = size
            feed["kernelsu"]["sha256"] = digest
            if kernelsu.get("updatesKernelSuReadme"):
                update_kernelsu_readme(module, ksud)
            changed.append("kernelsu")
            print(f"{target_id}: ksud {size} bytes {digest}")

    # Written once, after every target succeeded, so a mid-run failure never
    # leaves the feed describing artifacts that were not published.
    temporary = manifest_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    temporary.replace(manifest_path)

    output = pathlib.Path(os.environ["GITHUB_OUTPUT"])
    with output.open("a", encoding="utf-8") as handle:
        handle.write("paths=" + " ".join(sorted(set(changed))) + "\n")


if __name__ == "__main__":
    main()
