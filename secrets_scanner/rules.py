"""Detection rules.

Each rule has a cheap keyword prefilter (substring check on the lowercased text)
and a regex with a named group ``secret``. An optional validator can drop a match,
adjust its confidence, attach extra info, or widen the reported secret.
"""

from __future__ import annotations

import base64
import binascii
import re
import zlib
from dataclasses import dataclass, field
from typing import Callable, Optional

from .entropy import char_classes, is_hex, shannon_entropy


@dataclass
class Verdict:
    confidence: str
    extra: dict = field(default_factory=dict)
    secret: Optional[str] = None  # overrides the matched text, e.g. a whole PEM block


Validator = Callable[[str, "re.Match[str]", str], Optional[Verdict]]


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    pattern: re.Pattern
    keywords: tuple[str, ...]  # lowercase
    confidence: str = "medium"
    validate: Optional[Validator] = None
    generic: bool = False  # generic rules yield to specific ones on overlapping spans


# --- AWS ---------------------------------------------------------------------

def aws_account_from_key_id(key_id: str) -> Optional[str]:
    """Decode the AWS account ID embedded in an access key ID.

    Works offline for keys issued since ~2019; older keys decode to garbage,
    so treat the result as a hint rather than a fact.
    """
    try:
        decoded = base64.b32decode(key_id[4:])
    except (binascii.Error, ValueError):
        return None
    z = int.from_bytes(decoded[:6], "big")
    return f"{(z & 0x7FFFFFFFFF80) >> 7:012d}"


def _aws_key_id(secret: str, m: re.Match, text: str) -> Verdict:
    extra = {}
    account = aws_account_from_key_id(secret)
    if account:
        extra["aws_account_hint"] = account
    # ASIA keys are temporary STS credentials and almost always expired by the time they're found.
    return Verdict("high" if secret.startswith("AKIA") else "medium", extra)


def _aws_secret(secret: str, m: re.Match, text: str) -> Optional[Verdict]:
    if shannon_entropy(secret) < 4.0 or char_classes(secret) < 3:
        return None
    return Verdict("high")


# --- GitHub ------------------------------------------------------------------

_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _base62(n: int, width: int) -> str:
    out = ""
    while n:
        n, r = divmod(n, 62)
        out = _B62[r] + out
    return out.rjust(width, "0")


def github_checksum(payload: str) -> str:
    """Last 6 chars of a ghX_ token: base62(CRC32(30-char payload))."""
    return _base62(zlib.crc32(payload.encode()), 6)


def _github_token(secret: str, m: re.Match, text: str) -> Verdict:
    body = secret[4:]
    if github_checksum(body[:30]) == body[30:]:
        return Verdict("high", {"checksum": "valid"})
    return Verdict("medium", {"checksum": "mismatch"})


# --- Private keys ------------------------------------------------------------

_PEM_END = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")


def _private_key(secret: str, m: re.Match, text: str) -> Optional[Verdict]:
    end = _PEM_END.search(text, m.end(), m.end() + 20000)
    if not end:
        return None
    body = text[m.end():end.start()].replace("\\n", "\n")
    b64 = "".join(re.sub(r"[^A-Za-z0-9+/=]", "", line)
                  for line in body.splitlines() if ":" not in line)
    # A header string in code (e.g. a parser checking for "BEGIN PRIVATE KEY") has no real body.
    if len(b64) < 64:
        return None
    return Verdict("high", secret=text[m.start():end.end()])


# --- Generic high-entropy assignment -----------------------------------------

def _generic(secret: str, m: re.Match, text: str) -> Optional[Verdict]:
    end = m.end("secret")
    if end < len(text) and text[end] in "(.[":
        return None  # function call or attribute access, not a literal
    s = secret.rstrip("=")
    if is_hex(s):
        ok = (len(s) >= 20 and shannon_entropy(s) >= 3.0
              and any(c.isdigit() for c in s) and any(c.isalpha() for c in s))
    else:
        ok = char_classes(s) >= 3 and shannon_entropy(s) >= 3.5
    return Verdict("low") if ok else None


RULES: list[Rule] = [
    Rule(
        "aws-access-key-id", "AWS access key ID",
        re.compile(r"(?<![A-Z0-9])(?P<secret>(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})(?![A-Z0-9])"),
        ("akia", "asia", "abia", "acca"), validate=_aws_key_id,
    ),
    Rule(
        "aws-secret-access-key", "AWS secret access key",
        re.compile(r"(?i)aws.{0,20}?(?:secret|sk|private).{0,20}?[\s:=\"'>]+"
                   r"(?P<secret>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])"),
        ("aws",), validate=_aws_secret,
    ),
    Rule(
        "github-token", "GitHub token",
        re.compile(r"(?<![A-Za-z0-9_])(?P<secret>gh[pousr]_[A-Za-z0-9]{36})(?![A-Za-z0-9])"),
        ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"), validate=_github_token,
    ),
    Rule(
        "github-fine-grained-pat", "GitHub fine-grained personal access token",
        re.compile(r"(?P<secret>github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})(?![A-Za-z0-9])"),
        ("github_pat_",), confidence="high",
    ),
    Rule(
        "slack-token", "Slack token",
        re.compile(r"(?P<secret>xox[baprs]-[0-9A-Za-z-]{20,})"),
        ("xox",), confidence="high",
    ),
    Rule(
        "slack-webhook", "Slack incoming webhook URL",
        re.compile(r"(?P<secret>https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24})"),
        ("hooks.slack.com",), confidence="high",
    ),
    Rule(
        "stripe-live-key", "Stripe live secret/restricted key",
        re.compile(r"(?P<secret>(?:sk|rk)_live_[0-9A-Za-z]{24,99})"),
        ("_live_",), confidence="high",
    ),
    Rule(
        # Often intentionally public in browser apps, hence medium.
        "google-api-key", "Google API key",
        re.compile(r"(?P<secret>AIza[0-9A-Za-z_\-]{35})"),
        ("aiza",), confidence="medium",
    ),
    Rule(
        "anthropic-api-key", "Anthropic API key",
        re.compile(r"(?P<secret>sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,})"),
        ("sk-ant-",), confidence="high",
    ),
    Rule(
        "private-key", "Private key block",
        re.compile(r"(?P<secret>-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----)"),
        ("private key",), validate=_private_key,
    ),
    Rule(
        "generic-secret", "High-entropy value assigned to a secret-looking name",
        re.compile(r"(?i)(?:api[_-]?key|secret|token|passw(?:or)?d|pwd|auth|credential|access[_-]?key)"
                   r"[\w.-]{0,20}[\"']?\s*(?::=|=>|[:=])\s*[\"'`]?"
                   r"(?P<secret>[A-Za-z0-9+/_\-=]{16,128})"),
        ("key", "secret", "token", "passw", "pwd", "auth", "credential"),
        confidence="low", validate=_generic, generic=True,
    ),
]
