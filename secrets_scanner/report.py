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
    out += _exploited(rep["tools"])
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
            if "kev" in t:
                lines.append(f"| Actively exploited (CISA KEV) | {_kev_summary(t)} |")
    lines.append(f"| Exposed files | {len(rep['files'])} flagged |")
    return lines + [""]


def _kev_summary(t: dict) -> str:
    meta = t["kev"]
    if meta["status"] != "ok":
        return f"not checked: {meta['detail']}"
    hits = [v for v in t["vulnerabilities"] if v.get("kev")]
    ransom = sum(v["kev"]["ransomware"] for v in hits)
    text = f"**{len(hits)} CVEs**" + (f", {ransom} used in ransomware" if ransom else "")
    if meta["source"] == "stale-cache":
        text += f" (offline: KEV list is {meta['age_hours'] / 24:.0f} days old)"
    return text


def _exploited(tools: list[dict]) -> list[str]:
    t = next((t for t in tools if t["tool"] == "trivy" and t["status"] == "ok"), None)
    hits = [v for v in t["vulnerabilities"] if v.get("kev")] if t else []
    if not hits:
        return []
    lines = ["## Actively exploited (CISA KEV)", "",
             "Attackers are known to be exploiting these right now. Fix them before anything else.", "",
             "| CVE | Package | Installed | Fixed in | Ransomware | CISA's required action |",
             "|---|---|---|---|---|---|"]
    for v in hits:
        k = v["kev"]
        lines.append(f"| {v['id']} | {v['package']} | {v['installed']} | {v['fixed'] or 'no fix yet'} "
                     f"| {'**yes**' if k['ransomware'] else 'not known'} | {_cell(k['required_action'])} |")
    return lines + ["", "_Full CISA guidance for each CVE is in the JSON report._", ""]


def _cell(text: str, limit: int = 140) -> str:
    """Keep table cells readable: escape pipes and trim CISA's long boilerplate."""
    text = " ".join(text.split()).replace("|", "\\|")
    return text if len(text) <= limit else text[:limit].rsplit(" ", 1)[0] + "…"


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
    has_kev = t.get("kev", {}).get("status") == "ok"
    has_epss = t.get("epss", {}).get("status") == "ok"
    if t.get("epss", {}).get("status") == "error":
        lines += [f"> EPSS not added: {t['epss']['detail']}", ""]
    head = ["Severity", "CVE", "Package", "Installed", "Fixed in"]
    head += ["KEV"] * has_kev + ["EPSS (30-day)"] * has_epss
    lines += ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for v in vulns[:TOP_VULNS]:
        row = [v["severity"], v["id"], v["package"], v["installed"], v["fixed"] or "no fix yet"]
        if has_kev:
            row.append("**exploited**" if v.get("kev") else "")
        if has_epss:
            row.append(f"{v['epss']['score']:.1%}" if v.get("epss") else "n/a")
        lines.append("| " + " | ".join(row) + " |")
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
