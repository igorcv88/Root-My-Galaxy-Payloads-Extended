#!/usr/bin/env python3
"""Emit a target's KernelSU build settings as GitHub step outputs."""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

KEYS = ("kernelRelease", "ddkImage", "moduleName", "ksudName")


def main(target_id: str) -> None:
    targets = json.loads(
        (ROOT / ".github/build-targets.json").read_text(encoding="utf-8")
    )["targets"]
    kernelsu = targets[target_id]["kernelSu"]
    if kernelsu is None:
        raise SystemExit(f"{target_id} declares no reproducible KernelSU inputs")
    for key in KEYS:
        print(f"{key}={kernelsu[key]}")


if __name__ == "__main__":
    main(sys.argv[1])
