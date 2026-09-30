"""Combine file-audit, Lynis and Trivy results into one Markdown or JSON report."""

from __future__ import annotations

import datetime
import platform

from .sysaudit import SysFinding
from .vulnscan import SEVERITIES, ToolResult

TOP_VULNS = 30


def build(files: list[SysFinding], tools: list[ToolResult]) -> dict:
    return {
        "host": platform.node(),
        "platform": platform.platform(),
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
        "files": [f.to_dict() for f in files],
        "tools": [t.to_dict() for t in tools],
    }


def to_markdown(rep: dict) -> str:
    out = [f"# Security audit: {rep['host']}", "",
           f"- Platform: {rep['platform']}", f"- Generated: {rep['generated']}", ""]
    out += _summary(rep)
    for tool in rep["tools"]:
        out += _lynis(tool) if tool["tool"] == "lynis" else _trivy(tool)
    out += _files(rep["files"])
    return "\n".join(out) + "\n"


def _summary(rep: dict) -> list[str]:
    lines = ["## Summary", "", "| Check | Result |", "|---|---|"]
    for t in rep["tools"]:
        if t["status"] != "ok":
            lines.append(f"| {t['tool']} | {t['status']}: {t['detail']} |")
        elif t["tool"] == "lynis":
            lines.append(f"| Lynis hardening | index {t['hardening_index']}/100, "
                         f"{len(t['warnings'])} warnings, {len(t['suggestions'])} suggestions |")
        else:
            c = t["counts"]
            lines.append("| Trivy CVEs | " + ", ".join(f"{c[s]} {s.lower()}" for s in SEVERITIES if c[s])
                         + (" |" if any(c.values()) else "none found |"))
    lines.append(f"| Exposed files | {len(rep['files'])} flagged |")
    return lines + [""]


def _lynis(t: dict) -> list[str]:
    if t["status"] != "ok":
        return []
    lines = ["## Hardening (Lynis)", "", f"Hardening index: **{t['hardening_index']}/100**", ""]
    if t["warnings"]:
        lines += ["### Warnings", ""] + [f"- `{w['id']}` {w['message']}" for w in t["warnings"]] + [""]
    if t["suggestions"]:
        lines += ["### Suggestions", ""]
        for s in t["suggestions"]:
            fix = f" (fix: {s['solution']})" if "solution" in s else ""
            lines.append(f"- `{s['id']}` {s['message']}{fix}")
        lines.append("")
    return lines


def _trivy(t: dict) -> list[str]:
    if t["status"] != "ok":
        return []
    os_name = " ".join(filter(None, (t["os"].get("Family"), t["os"].get("Name")))) or "unknown OS"
    lines = ["## Known vulnerabilities (Trivy)", "", f"Detected OS: {os_name}", ""]
    if t["detail"]:
        lines += [f"> {t['detail']}", ""]
    vulns = t["vulnerabilities"]
    if not vulns:
        return lines + ["No known vulnerabilities found.", ""]
    lines += ["| Severity | CVE | Package | Installed | Fixed in |", "|---|---|---|---|---|"]
    for v in vulns[:TOP_VULNS]:
        lines.append(f"| {v['severity']} | {v['id']} | {v['package']} | {v['installed']} "
                     f"| {v['fixed'] or 'no fix yet'} |")
    if len(vulns) > TOP_VULNS:
        lines.append(f"\n_{len(vulns) - TOP_VULNS} more in the JSON report._")
    return lines + [""]


def _files(files: list[dict]) -> list[str]:
    lines = ["## Exposed credentials and unencrypted files", ""]
    if not files:
        return lines + ["Nothing flagged.", ""]
    lines += ["| Category | Path | Mode | Embedded secrets |", "|---|---|---|---|"]
    for f in files:
        secrets = ", ".join(s["rule"] for s in f["embedded_secrets"]) or "-"
        lines.append(f"| {f['category']} | `{f['path']}` | {f['mode']} | {secrets} |")
    return lines + [""]
