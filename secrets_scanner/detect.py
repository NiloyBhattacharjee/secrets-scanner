"""Scan a chunk of text with the rules and apply false-positive filtering."""

from __future__ import annotations

import bisect
import fnmatch
import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional

from .rules import RULES, Rule, Verdict

CONFIDENCE = ("low", "medium", "high")
ALLOW_MARKER = "secrets-scanner:allow"

_PLACEHOLDER = re.compile(
    r"(?i)example|placeholder|dummy|changeme|sample|fake|redacted|your|xxxx|\*\*\*|0{6}|123456"
)

# Files where high-entropy strings are expected and never secrets.
SKIP_GLOBS = (
    "*.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum",
    "*.min.js", "*.min.css", "*.map", "*.svg",
)
_TEST_PATH = re.compile(
    r"(?i)(^|/)(tests?|spec|fixtures?|examples?|mocks?|testdata)(/|$)|(_test|\.test|\.spec)\.\w+$"
)


@dataclass
class Finding:
    rule_id: str
    description: str
    secret: str
    line: int
    column: int
    confidence: str
    path: Optional[str] = None
    blob: Optional[str] = None
    commit: Optional[str] = None
    author: Optional[str] = None
    date: Optional[str] = None
    extra: dict = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.rule_id}:{self.secret}".encode()).hexdigest()[:16]

    def redacted(self) -> str:
        first = self.secret.splitlines()[0] if self.rule_id == "private-key" else self.secret[:6]
        return f"{first}…({len(self.secret)} chars)"

    def to_dict(self, show_secret: bool = False) -> dict:
        return {
            "rule": self.rule_id,
            "description": self.description,
            "confidence": self.confidence,
            "secret": self.secret if show_secret else self.redacted(),
            "fingerprint": self.fingerprint,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "blob": self.blob,
            "commit": self.commit,
            "author": self.author,
            "date": self.date,
            **self.extra,
        }


def looks_like_placeholder(s: str) -> bool:
    return bool(_PLACEHOLDER.search(s)) or len(set(s)) < 6


def is_binary(data: bytes) -> bool:
    return b"\0" in data[:8000]


def scan_text(text: str, rules: list[Rule] = RULES) -> list[Finding]:
    lower = text.lower()
    hits: list[tuple[int, int, Rule, str, Verdict]] = []
    for rule in rules:
        if not any(k in lower for k in rule.keywords):
            continue
        for m in rule.pattern.finditer(text):
            secret = m.group("secret")
            if looks_like_placeholder(secret):
                continue
            verdict = rule.validate(secret, m, text) if rule.validate else Verdict(rule.confidence)
            if verdict is None:
                continue
            start, end = m.span("secret")
            hits.append((start, end, rule, verdict.secret or secret, verdict))

    if not hits:
        return []

    specific = [(s, e) for s, e, r, _, _ in hits if not r.generic]
    line_starts = [0] + [m.end() for m in re.finditer("\n", text)]
    findings = []
    seen = set()
    for start, end, rule, secret, verdict in hits:
        if rule.generic and any(s < end and start < e for s, e in specific):
            continue
        idx = bisect.bisect_right(line_starts, start) - 1
        line_start = line_starts[idx]
        line_end = text.find("\n", line_start)
        if ALLOW_MARKER in text[line_start:line_end if line_end != -1 else None]:
            continue
        key = (rule.id, secret, idx)
        if key in seen:
            continue
        seen.add(key)
        findings.append(Finding(
            rule_id=rule.id, description=rule.description, secret=secret,
            line=idx + 1, column=start - line_start + 1,
            confidence=verdict.confidence, extra=dict(verdict.extra),
        ))
    return findings


def should_skip_path(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(name, g) for g in SKIP_GLOBS)


def is_test_path(path: str) -> bool:
    return bool(_TEST_PATH.search(path))


def downgrade(confidence: str) -> str:
    return CONFIDENCE[max(0, CONFIDENCE.index(confidence) - 1)]


def apply_path_policy(findings: list[Finding]) -> list[Finding]:
    """Drop findings in lockfiles etc.; downgrade (not drop) findings under test paths."""
    out = []
    for f in findings:
        if f.path:
            p = f.path.replace("\\", "/")
            if should_skip_path(p):
                continue
            if is_test_path(p):
                f.confidence = downgrade(f.confidence)
                f.extra["test_path"] = True
        out.append(f)
    return out


def at_least(findings: list[Finding], min_confidence: str) -> list[Finding]:
    floor = CONFIDENCE.index(min_confidence)
    return [f for f in findings if CONFIDENCE.index(f.confidence) >= floor]
