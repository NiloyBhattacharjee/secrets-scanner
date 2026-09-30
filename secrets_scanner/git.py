"""Thin wrappers over git plumbing commands."""

from __future__ import annotations

import re
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator


class GitError(RuntimeError):
    pass


def git(repo: str | Path, *args: str) -> bytes:
    r = subprocess.run(
        ["git", "-C", str(repo), "-c", "core.quotepath=off", *args],
        capture_output=True,
    )
    if r.returncode:
        raise GitError(r.stderr.decode(errors="replace").strip())
    return r.stdout


def all_blobs(repo, max_size: int) -> list[str]:
    """Every blob in the object store, reachable or not (dangling objects included)."""
    out = git(repo, "cat-file", "--batch-all-objects",
              "--batch-check=%(objectname) %(objecttype) %(objectsize)")
    shas = []
    for line in out.splitlines():
        sha, typ, size = line.split()
        if typ == b"blob" and int(size) <= max_size:
            shas.append(sha.decode())
    return shas


def read_blobs(repo, shas: Iterable[str]) -> Iterator[tuple[str, bytes]]:
    """Stream blob contents through a single `git cat-file --batch` process."""
    shas = list(shas)
    proc = subprocess.Popen(["git", "-C", str(repo), "cat-file", "--batch"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def feed():
        try:
            for s in shas:
                proc.stdin.write(s.encode() + b"\n")
        finally:
            proc.stdin.close()

    # Write from a thread so a full stdout pipe can't deadlock us.
    writer = threading.Thread(target=feed, daemon=True)
    writer.start()
    try:
        for _ in shas:
            header = proc.stdout.readline().split()
            if len(header) != 3:  # "<sha> missing"
                continue
            data = proc.stdout.read(int(header[2]))
            proc.stdout.read(1)  # trailing newline
            yield header[0].decode(), data
    finally:
        writer.join()
        proc.stdout.close()
        proc.wait()


@dataclass
class Commit:
    sha: str
    author: str
    email: str
    date: str
    paths: list[str]


def blob_history(repo, blob: str) -> list[Commit]:
    """Commits (oldest first) that added, changed or removed this blob, with its paths."""
    out = git(repo, "log", "--all", "--reflog", "--reverse", "--name-only",
              "--format=%x00%H%x1f%an%x1f%ae%x1f%aI", f"--find-object={blob}")
    commits = []
    for chunk in out.decode("utf-8", "replace").split("\0")[1:]:
        lines = chunk.strip("\n").split("\n")
        sha, author, email, date = lines[0].split("\x1f")
        commits.append(Commit(sha, author, email, date, [l for l in lines[1:] if l]))
    return commits


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


@dataclass
class StagedFile:
    path: str
    blob: str
    added_lines: set[int]


def staged_files(repo) -> list[StagedFile]:
    """Staged files with the line numbers added in this commit."""
    diff = git(repo, "diff", "--cached", "-U0", "--no-color", "--no-ext-diff",
               "--src-prefix=a/", "--dst-prefix=b/", "--diff-filter=ACMR")
    added: dict[str, set[int]] = {}
    current = None
    for line in diff.decode("utf-8", "replace").splitlines():
        if line.startswith("+++ "):
            current = line[6:] if line.startswith("+++ b/") else None
            if current is not None:
                added.setdefault(current, set())
        elif current and (m := _HUNK.match(line)):
            start, count = int(m.group(1)), int(m.group(2) or 1)
            added[current].update(range(start, start + count))
    if not added:
        return []

    blobs = {}
    for entry in git(repo, "ls-files", "--stage", "-z").split(b"\0"):
        if entry:
            meta, path = entry.decode("utf-8", "replace").split("\t", 1)
            blobs[path] = meta.split()[1]
    return [StagedFile(p, blobs[p], lines) for p, lines in added.items() if lines and p in blobs]


def hooks_dir(repo) -> Path:
    path = git(repo, "rev-parse", "--git-path", "hooks").decode().strip()
    p = Path(path)
    return p if p.is_absolute() else Path(repo) / p
