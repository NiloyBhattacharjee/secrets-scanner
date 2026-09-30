"""Run Lynis and Trivy, if installed, and normalise their results.

Lynis audits system hardening (configuration, permissions, services, kernel settings).
Trivy matches installed OS and language packages against known CVE databases.
Both are optional: a missing tool is reported as skipped, not as an error.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
TRIVY_SKIP_DIRS = ("/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker", "/mnt", "/media")

# Mounts that are not part of this Linux system: WSL's Windows drives (drvfs/9p),
# network shares, and removable-media filesystems. Scanning them is slow and can crash Trivy.
FOREIGN_FS_TYPES = frozenset({
    "drvfs", "9p", "virtiofs", "cifs", "smb3", "smbfs", "nfs", "nfs4",
    "fuse.sshfs", "fuse.rclone", "vfat", "exfat", "ntfs", "ntfs3", "fuseblk",
})


def _unescape_mount(path: str) -> str:
    """/proc/mounts writes spaces etc. as octal escapes, e.g. '\\040'."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), path)


def foreign_mounts(mounts_text: str) -> list[str]:
    """Mount points in /proc/mounts format whose filesystem type is in FOREIGN_FS_TYPES."""
    out = []
    for line in mounts_text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] in FOREIGN_FS_TYPES and parts[1] != "/":
            out.append(_unescape_mount(parts[1]))
    return out


def trivy_skip_dirs() -> list[str]:
    skip = list(TRIVY_SKIP_DIRS)
    try:
        with open("/proc/mounts", encoding="utf-8") as f:
            extra = foreign_mounts(f.read())
    except OSError:
        extra = []
    return skip + [m for m in extra if not any(m == s or m.startswith(s + "/") for s in skip)]


@dataclass
class ToolResult:
    tool: str
    status: str                      # "ok" | "skipped" | "error"
    detail: str = ""
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"tool": self.tool, "status": self.status, "detail": self.detail, **self.data}


# --- Lynis -------------------------------------------------------------------

def parse_lynis_report(text: str) -> dict:
    """Parse a lynis-report.dat file (key=value lines; list keys end in [])."""
    warnings, suggestions, index = [], [], None
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if not sep:
            continue
        if key == "hardening_index":
            index = int(value) if value.isdigit() else None
        elif key in ("warning[]", "suggestion[]"):
            # Format: TEST-ID|message|details|solution|
            parts = value.split("|")
            item = {"id": parts[0], "message": parts[1] if len(parts) > 1 else ""}
            if len(parts) > 3 and parts[3] not in ("", "-"):
                item["solution"] = parts[3]
            (warnings if key == "warning[]" else suggestions).append(item)
    return {"hardening_index": index, "warnings": warnings, "suggestions": suggestions}


def run_lynis(timeout: int = 1800) -> ToolResult:
    exe = shutil.which("lynis")
    if not exe:
        return ToolResult("lynis", "skipped", "not installed (sudo apt install lynis)")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        return ToolResult("lynis", "skipped", "needs root for a full audit (re-run with sudo)")
    with tempfile.TemporaryDirectory() as tmp:
        report = os.path.join(tmp, "lynis-report.dat")
        try:
            subprocess.run(
                [exe, "audit", "system", "--quiet", "--no-colors",
                 "--report-file", report, "--logfile", os.path.join(tmp, "lynis.log")],
                capture_output=True, text=True, timeout=timeout,
            )
            with open(report, encoding="utf-8", errors="replace") as f:
                data = parse_lynis_report(f.read())
        except (OSError, subprocess.TimeoutExpired) as e:
            return ToolResult("lynis", "error", str(e))
    return ToolResult("lynis", "ok", data=data)


# --- Trivy -------------------------------------------------------------------

def parse_trivy_json(doc: dict) -> dict:
    """Flatten Trivy JSON output into de-duplicated vulnerabilities plus severity counts."""
    seen, vulns = set(), []
    for result in doc.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            key = (v.get("VulnerabilityID"), v.get("PkgName"), v.get("InstalledVersion"))
            if key in seen:
                continue
            seen.add(key)
            vulns.append({
                "id": v.get("VulnerabilityID"),
                "package": v.get("PkgName"),
                "installed": v.get("InstalledVersion"),
                "fixed": v.get("FixedVersion") or None,
                "severity": v.get("Severity", "UNKNOWN"),
                "title": v.get("Title") or "",
                "target": result.get("Target"),
            })
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    vulns.sort(key=lambda v: (rank.get(v["severity"], len(SEVERITIES)), v["fixed"] is None, v["id"] or ""))
    counts = {s: sum(v["severity"] == s for v in vulns) for s in SEVERITIES}
    os_info = (doc.get("Metadata") or {}).get("OS") or {}
    return {"os": os_info, "counts": counts, "vulnerabilities": vulns}


def run_trivy(target: str = "/", timeout: int = 1800) -> ToolResult:
    exe = shutil.which("trivy")
    if not exe:
        return ToolResult("trivy", "skipped", "not installed (sudo apt install trivy)")
    cmd = [exe, "rootfs", "--scanners", "vuln", "--format", "json", "--quiet",
           "--skip-dirs", ",".join(trivy_skip_dirs()), target]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return ToolResult("trivy", "error", str(e))
    if proc.returncode != 0 or not proc.stdout.strip():
        return ToolResult("trivy", "error", proc.stderr.strip()[-500:] or f"exit {proc.returncode}")
    try:
        data = parse_trivy_json(json.loads(proc.stdout))
    except json.JSONDecodeError as e:
        return ToolResult("trivy", "error", f"bad JSON from trivy: {e}")
    detail = "" if data["os"] else "OS not recognised; only language packages were checked"
    return ToolResult("trivy", "ok", detail, data)
