"""Baseline file: fingerprints of findings that were reviewed and accepted."""

from __future__ import annotations

import json
from pathlib import Path

from .detect import Finding


def load(path: str | Path) -> set[str]:
    p = Path(path)
    if not p.exists():
        return set()
    return {e["fingerprint"] for e in json.loads(p.read_text(encoding="utf-8"))["findings"]}


def write(path: str | Path, findings: list[Finding]) -> None:
    entries = sorted(
        ({"fingerprint": f.fingerprint, "rule": f.rule_id, "secret": f.redacted(), "path": f.path}
         for f in findings),
        key=lambda e: (e["path"] or "", e["rule"]),
    )
    Path(path).write_text(json.dumps({"version": 1, "findings": entries}, indent=2) + "\n",
                          encoding="utf-8")


def exclude(findings: list[Finding], fingerprints: set[str]) -> list[Finding]:
    return [f for f in findings if f.fingerprint not in fingerprints]
