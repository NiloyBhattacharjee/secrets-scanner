from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import baseline, git, report, scanner, sysaudit, vulnscan
from .detect import CONFIDENCE, Finding, at_least

HOOK_MARKER = "# installed by secrets-scanner"


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--show-secrets", action="store_true", help="print full secrets (careful)")
    p.add_argument("--min-confidence", choices=CONFIDENCE, default="low")
    p.add_argument("--baseline", metavar="FILE", help="ignore findings recorded in this baseline")
    p.add_argument("--write-baseline", metavar="FILE", help="record current findings as accepted")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secrets-scan", description="Find leaked secrets in git repos.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("history", help="scan every blob in the repo's object store")
    p.add_argument("repo", nargs="?", default=".")
    p.add_argument("--max-blob-size", type=int, default=scanner.DEFAULT_MAX_BLOB)
    _common(p)

    p = sub.add_parser("staged", help="scan lines added in the index (pre-commit)")
    p.add_argument("repo", nargs="?", default=".")
    _common(p)

    p = sub.add_parser("files", help="scan files/directories on disk")
    p.add_argument("paths", nargs="+")
    _common(p)

    p = sub.add_parser("system", help="audit a filesystem for credential files and unencrypted sensitive data")
    p.add_argument("paths", nargs="+", help="directories to walk (e.g. /home /etc)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--no-peek", action="store_true", help="do not open flagged files to scan for secrets")

    p = sub.add_parser("audit", help="full audit: Lynis + Trivy + exposed-file scan, one report")
    p.add_argument("paths", nargs="*", default=["/home", "/root", "/etc", "/opt", "/srv", "/var/www"],
                   help="directories for the exposed-file scan")
    p.add_argument("--output", "-o", metavar="FILE", help="write the report here (.json for JSON, else Markdown)")
    p.add_argument("--skip-lynis", action="store_true")
    p.add_argument("--skip-trivy", action="store_true")

    p = sub.add_parser("install-hook", help="install a git pre-commit hook")
    p.add_argument("repo", nargs="?", default=".")
    p.add_argument("--min-confidence", choices=CONFIDENCE, default="medium")
    p.add_argument("--force", action="store_true", help="overwrite an existing pre-commit hook")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "install-hook":
            return install_hook(args)
        if args.command == "system":
            return run_system(args)
        if args.command == "audit":
            return run_audit(args)
        if args.command == "history":
            findings = scanner.scan_history(args.repo, args.max_blob_size)
        elif args.command == "staged":
            findings = scanner.scan_staged(args.repo)
        else:
            findings = scanner.scan_paths(args.paths)
    except git.GitError as e:
        print(f"git error: {e}", file=sys.stderr)
        return 2

    findings = at_least(findings, args.min_confidence)
    if args.write_baseline:
        baseline.write(args.write_baseline, findings)
        print(f"wrote {len(findings)} findings to {args.write_baseline}", file=sys.stderr)
        return 0
    if args.baseline:
        findings = baseline.exclude(findings, baseline.load(args.baseline))

    order = {c: i for i, c in enumerate(reversed(CONFIDENCE))}
    findings.sort(key=lambda f: (order[f.confidence], f.path or "", f.line))
    if args.json:
        print(json.dumps([f.to_dict(args.show_secrets) for f in findings], indent=2))
    else:
        for f in findings:
            print(_format(f, args.show_secrets))
        _summary(findings, args.command == "staged")
    return 1 if findings else 0


def _format(f: Finding, show: bool) -> str:
    secret = f.secret if show else f.redacted()
    lines = [f"[{f.confidence.upper()}] {f.rule_id}  {secret}",
             f"    at {f.path or '<unknown path>'}:{f.line}:{f.column}"]
    if f.commit:
        more = f", in {f.extra['blobs']} file versions" if f.extra.get("blobs", 1) > 1 else ""
        lines.append(f"    introduced in {f.commit[:10]} by {f.author} on {f.date}{more}")
    elif f.extra.get("unreachable"):
        lines.append(f"    blob {f.blob[:10]} is unreachable (history was rewritten, object still present)")
    if acct := f.extra.get("aws_account_hint"):
        lines.append(f"    decoded AWS account: {acct}")
    if f.extra.get("test_path"):
        lines.append("    (test path: confidence lowered)")
    return "\n".join(lines)


def _summary(findings: list[Finding], staged: bool) -> None:
    if not findings:
        print("no secrets found", file=sys.stderr)
        return
    counts = {c: sum(f.confidence == c for f in findings) for c in CONFIDENCE}
    print(f"\n{len(findings)} findings ({counts['high']} high, {counts['medium']} medium, "
          f"{counts['low']} low)", file=sys.stderr)
    if staged:
        print("commit blocked. Remove the secret, add 'secrets-scanner:allow' to the line, "
              "or bypass with --no-verify.", file=sys.stderr)


def run_system(args) -> int:
    findings = sysaudit.audit_paths(args.paths, peek_secrets=not args.no_peek)
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        for f in findings:
            print(_format_sys(f))
        by_cat = {}
        for f in findings:
            by_cat[f.category] = by_cat.get(f.category, 0) + 1
        summary = ", ".join(f"{n} {c}" for c, n in sorted(by_cat.items())) or "nothing"
        print(f"\n{len(findings)} files flagged ({summary})", file=sys.stderr)
        print("Review each: move secrets to a secrets manager, encrypt or delete "
              "sensitive files, and tighten file permissions.", file=sys.stderr)
    return 1 if findings else 0


def run_audit(args) -> int:
    tools = []
    if not args.skip_lynis:
        print("running lynis (a few minutes)...", file=sys.stderr)
        tools.append(vulnscan.run_lynis())
    if not args.skip_trivy:
        print("running trivy (first run downloads the CVE database)...", file=sys.stderr)
        tools.append(vulnscan.run_trivy())
    print("scanning for exposed credentials and files...", file=sys.stderr)
    files = sysaudit.audit_paths([p for p in args.paths if Path(p).exists()])

    rep = report.build(files, tools)
    text = json.dumps(rep, indent=2) if (args.output or "").endswith(".json") else report.to_markdown(rep)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"report written to {args.output}", file=sys.stderr)
    else:
        print(text)
    for t in tools:
        if t.status != "ok":
            print(f"note: {t.tool} {t.status}: {t.detail}", file=sys.stderr)
    return 1 if files or any(t.data.get("warnings") or t.data.get("vulnerabilities") for t in tools) else 0


def _format_sys(f: sysaudit.SysFinding) -> str:
    lines = [f"[{f.category}] {f.path}",
             f"    {f.reason}  ({f.size} bytes, mode {f.mode})"]
    for s in f.secrets:
        lines.append(f"    -> secret: [{s.confidence.upper()}] {s.rule_id} at line {s.line}")
    return "\n".join(lines)


def install_hook(args) -> int:
    hook = git.hooks_dir(args.repo) / "pre-commit"
    if hook.exists() and HOOK_MARKER not in hook.read_text(errors="replace") and not args.force:
        print(f"{hook} already exists; use --force to overwrite", file=sys.stderr)
        return 2
    pkg_parent = Path(__file__).resolve().parent.parent.as_posix()
    python = Path(sys.executable).as_posix()
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(
        "#!/bin/sh\n"
        f"{HOOK_MARKER}\n"
        f'PYTHONPATH="{pkg_parent}${{PYTHONPATH:+{os.pathsep}$PYTHONPATH}}" '
        f'exec "{python}" -m secrets_scanner staged --min-confidence {args.min_confidence}\n',
        encoding="utf-8", newline="\n",
    )
    hook.chmod(0o755)
    print(f"installed {hook}")
    return 0
