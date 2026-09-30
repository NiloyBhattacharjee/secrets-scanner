"""Filesystem audit: find leftover credential files and unencrypted sensitive files.

This complements the git-history scanner. Where that tool finds secrets *inside*
tracked source, this one walks a live filesystem and reports files that commonly
hold credentials or sensitive data in the clear, so they can be secured or removed.

It only reads and reports. It never transmits, modifies, or exfiltrates anything.
Run it only on systems you own or are explicitly authorised to audit.
"""

from __future__ import annotations

import fnmatch
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from .detect import Finding, is_binary, scan_text

# Files whose very presence is worth flagging: they usually hold credentials,
# keys, or session material in the clear.
CREDENTIAL_FILES = (
    ".env", ".env.*", "*.env",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",          # private SSH keys
    "*.pem", "*.key", "*.pfx", "*.p12", "*.keystore", "*.jks",
    ".netrc", "_netrc", ".pgpass", ".my.cnf",
    ".htpasswd", "credentials", "credentials.json",
    ".aws/credentials", ".docker/config.json",
    "*.kdbx", "*.ovpn", "*.ppk",
    "shadow", "master.key", "secret_key_base",
    "*.sqlite", "*.db",                                    # often hold session tokens/PII
    "wp-config.php", "settings.py", "config.php", "web.config",
)

# Extensions we treat as "unencrypted sensitive data" only when the name also
# hints at sensitivity (see SENSITIVE_NAME).
SENSITIVE_DATA_GLOBS = (
    "*.bak", "*.old", "*.orig", "*.swp", "*.sql", "*.dump", "*.csv", "*.xlsx",
)
SENSITIVE_NAME = (
    "backup", "dump", "secret", "password", "passwd", "credential", "private",
    "confidential", "token", "apikey", "api_key", "customer", "payroll",
    "ssn", "export",
)

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".tox",
    "proc", "sys", "dev", "run", "snap",
}

# PEM markers that indicate a real private key body rather than a public cert.
_PRIVATE_KEY_MARKER = b"PRIVATE KEY"


@dataclass
class SysFinding:
    path: str
    category: str          # "credential-file" | "unencrypted-sensitive" | "world-readable-secret"
    reason: str
    size: int
    mode: str
    secrets: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "category": self.category,
            "reason": self.reason,
            "size": self.size,
            "mode": self.mode,
            "embedded_secrets": [s.to_dict() for s in self.secrets],
        }


def _matches(name: str, globs: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(name, g) for g in globs)


def _name_is_sensitive(name: str) -> bool:
    low = name.lower()
    return any(h in low for h in SENSITIVE_NAME)


def _mode_str(st: os.stat_result) -> str:
    return stat.filemode(st.st_mode)


def _is_world_or_group_readable(st: os.stat_result) -> bool:
    return bool(st.st_mode & (stat.S_IRGRP | stat.S_IROTH))


def classify(path: Path, st: os.stat_result) -> tuple[str, str] | None:
    """Return (category, reason) if the file is worth flagging, else None."""
    name = path.name
    rel = path.as_posix()

    if _matches(name, CREDENTIAL_FILES) or path.match(".aws/credentials") \
            or path.match(".docker/config.json"):
        cat = "credential-file"
        # A private key or credential file readable by group/other is worse.
        if _is_world_or_group_readable(st) and name in (
            "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".env",
        ):
            cat = "world-readable-secret"
        return cat, f"known credential-bearing filename ({name})"

    if _matches(name, SENSITIVE_DATA_GLOBS) and _name_is_sensitive(name):
        return "unencrypted-sensitive", f"sensitive-looking data file left in the clear ({name})"

    return None


def _looks_encrypted(data: bytes) -> bool:
    """Rough check: high-entropy binary with no PEM/text structure looks encrypted."""
    if _PRIVATE_KEY_MARKER in data[:200]:
        return False
    if not is_binary(data):
        return False
    # Encrypted blobs have near-uniform byte distribution; a cheap proxy is a
    # high count of distinct byte values in the first chunk.
    return len(set(data[:4096])) > 200


def audit_paths(
    roots: list[str],
    max_size: int = 5 * 1024 * 1024,
    peek_secrets: bool = True,
) -> list[SysFinding]:
    """Walk each root, flag credential/sensitive files, and scan text ones for secrets."""
    results: list[SysFinding] = []
    for root in roots:
        for path in _walk(Path(root)):
            try:
                st = path.stat()
            except OSError:
                continue
            verdict = classify(path, st)
            if verdict is None:
                continue
            category, reason = verdict
            finding = SysFinding(
                path=path.as_posix(),
                category=category,
                reason=reason,
                size=st.st_size,
                mode=_mode_str(st),
            )
            if peek_secrets and st.st_size <= max_size:
                try:
                    data = path.read_bytes()
                except OSError:
                    data = b""
                if data and not _looks_encrypted(data) and not is_binary(data):
                    for f in scan_text(data.decode("utf-8", "replace")):
                        f.path = path.as_posix()
                        finding.secrets.append(f)
                if _looks_encrypted(data):
                    finding.reason += " [appears encrypted]"
            results.append(finding)
    return results


def _walk(root: Path):
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield Path(dirpath) / name
