#!/usr/bin/env python3
"""Per-target build assertions, driven by .github/build-targets.json.

The CZG3 assertions used to be inlined in the workflow, which is why the
workflow could only ever build CZG3. They live here now so every target
carries its own expected label, size, required helper strings and forbidden
diagnostic markers.
"""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]


def contains(path: pathlib.Path, needle: str) -> bool:
    return needle.encode("utf-8") in path.read_bytes()


def main(target_id: str) -> None:
    entry = json.loads(
        (ROOT / ".github/build-targets.json").read_text(encoding="utf-8")
    )["targets"][target_id]

    build = ROOT / "build" / target_id
    payload = build / "cve-2026-43499-app.release.so"
    helper = build / "cve-2026-43499-root"

    problems: list[str] = []
    for path in (payload, helper):
        if not path.is_file() or path.stat().st_size == 0:
            problems.append(f"missing or empty artifact: {path.relative_to(ROOT)}")
    if problems:
        raise SystemExit("\n".join(problems))

    expected_size = entry.get("expectedExploitSize")
    if expected_size is not None and payload.stat().st_size != expected_size:
        problems.append(
            f"exploit size {payload.stat().st_size} != expected {expected_size}"
        )

    label = entry["expectedLabel"]
    if not contains(payload, label):
        problems.append(f"build variant label '{label}' not found in the payload")

    for needle in entry.get("requiredHelperStrings", []):
        if not contains(helper, needle):
            problems.append(f"root helper is missing required string '{needle}'")

    for marker in entry.get("forbiddenMarkers", []):
        if contains(payload, marker):
            problems.append(f"unexpected diagnostic marker in the payload: {marker}")

    if problems:
        for problem in problems:
            print(f"::error::{target_id}: {problem}", file=sys.stderr)
        raise SystemExit(1)

    print(f"{target_id}: build verified ({payload.stat().st_size} bytes, {label})")


if __name__ == "__main__":
    main(sys.argv[1])
