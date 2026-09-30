"""High-level scan modes: full history, staged changes, and plain files."""

from __future__ import annotations

import os
from pathlib import Path

from . import git
from .detect import Finding, apply_path_policy, is_binary, scan_text

DEFAULT_MAX_BLOB = 2 * 1024 * 1024
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox"}


def _decode(data: bytes) -> str:
    return data.decode("utf-8", "replace")


def scan_history(repo, max_blob_size: int = DEFAULT_MAX_BLOB) -> list[Finding]:
    """Scan every blob in the repo once, then attribute hits to the commit that introduced them."""
    by_fp: dict[str, Finding] = {}
    for blob, data in git.read_blobs(repo, git.all_blobs(repo, max_blob_size)):
        if is_binary(data):
            continue
        findings = scan_text(_decode(data))
        if not findings:
            continue
        history = git.blob_history(repo, blob)
        first = next((c for c in history if c.paths), None)
        for f in findings:
            f.blob = blob
            if first:
                f.commit, f.author, f.date = first.sha, f"{first.author} <{first.email}>", first.date
                f.path = first.paths[0]
                f.extra["commits"] = len(history)
            else:
                f.extra["unreachable"] = True
            f.extra["blobs"] = 1
            prev = by_fp.get(f.fingerprint)
            if prev is None:
                by_fp[f.fingerprint] = f
                continue
            # Same secret in several file versions: keep the earliest reachable one.
            keep = f if _earlier(f, prev) else prev
            keep.extra["blobs"] = prev.extra["blobs"] + 1
            by_fp[f.fingerprint] = keep
    return apply_path_policy(list(by_fp.values()))


def _earlier(a: Finding, b: Finding) -> bool:
    """Reachable (dated) findings sort before unreachable ones."""
    if a.date and not b.date:
        return True
    return bool(a.date and b.date and a.date < b.date)


def scan_staged(repo) -> list[Finding]:
    """Scan only lines added in the index — fast enough for a pre-commit hook."""
    staged = git.staged_files(repo)
    by_blob = {s.blob: s for s in staged}
    results = []
    for blob, data in git.read_blobs(repo, by_blob):
        if is_binary(data):
            continue
        sf = by_blob[blob]
        for f in scan_text(_decode(data)):
            if f.line in sf.added_lines:
                f.path, f.blob = sf.path, blob
                results.append(f)
    return apply_path_policy(results)


def scan_paths(paths: list[str], max_size: int = DEFAULT_MAX_BLOB) -> list[Finding]:
    results = []
    for root in paths:
        for file in _walk(Path(root)):
            try:
                if file.stat().st_size > max_size:
                    continue
                data = file.read_bytes()
            except OSError:
                continue
            if is_binary(data):
                continue
            for f in scan_text(_decode(data)):
                f.path = file.as_posix()
                results.append(f)
    return apply_path_policy(results)


def _walk(root: Path):
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield Path(dirpath) / name
