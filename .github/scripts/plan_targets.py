#!/usr/bin/env python3
"""Resolve the workflow target selection into a build matrix.

The workflow is target-agnostic: this script is the only place that decides
which targets a run touches. A target must be declared in
`.github/build-targets.json`, must have a `src/targets/<id>/target.h`, and -
when KernelSU is being rebuilt - must declare reproducible KernelSU inputs.
Targets that are not selected are never rebuilt and never republished.
"""
from __future__ import annotations

import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]


def fail(message: str) -> "None":
    print(f"::error::{message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    descriptor = json.loads(
        (ROOT / ".github/build-targets.json").read_text(encoding="utf-8")
    )["targets"]
    manifest = json.loads(
        (ROOT / "support/targets-v3.json").read_text(encoding="utf-8")
    )
    published = {item["payloadId"] for item in manifest.get("payloads", [])}

    selection = os.environ.get("TARGET_SELECTION", "all").strip() or "all"
    mode = os.environ.get("UPDATE_MODE", "")

    if selection == "all":
        selected = sorted(descriptor)
    else:
        selected = [item.strip() for item in selection.split(",") if item.strip()]
        unknown = [item for item in selected if item not in descriptor]
        if unknown:
            fail(
                "Unknown target(s): "
                + ", ".join(unknown)
                + ". Declare them in .github/build-targets.json first."
            )

    matrix = []
    for target_id in selected:
        entry = descriptor[target_id]
        if not (ROOT / "src/targets" / target_id / "target.h").is_file():
            fail(f"{target_id}: src/targets/{target_id}/target.h is missing")
        if target_id not in published:
            fail(f"{target_id}: not present in support/targets-v3.json")

        build_kernelsu = "KernelSU" in mode and entry.get("kernelSu") is not None
        if "KernelSU" in mode and entry.get("kernelSu") is None:
            print(
                f"::notice::{target_id}: KernelSU inputs are not reproducible in "
                "CI; the published module and ksud are preserved unchanged."
            )
        if "Exploit" not in mode and not build_kernelsu:
            print(f"::notice::{target_id}: nothing to rebuild for mode '{mode}'")
            continue

        matrix.append(
            {
                "id": target_id,
                "artifactDir": entry["artifactDir"],
                "buildExploit": "Exploit" in mode,
                "buildKernelSu": build_kernelsu,
            }
        )

    if not matrix:
        fail(f"No target has anything to rebuild for mode '{mode}'")

    output = pathlib.Path(os.environ["GITHUB_OUTPUT"])
    with output.open("a", encoding="utf-8") as handle:
        handle.write("matrix=" + json.dumps({"include": matrix}) + "\n")
        handle.write("targets=" + ",".join(item["id"] for item in matrix) + "\n")
    print("Planned targets: " + ", ".join(item["id"] for item in matrix))


if __name__ == "__main__":
    main()
