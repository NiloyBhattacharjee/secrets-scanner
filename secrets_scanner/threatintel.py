"""Exploitation intelligence for CVEs found by Trivy.

- CISA KEV (Known Exploited Vulnerabilities): CVEs with evidence of active exploitation.
  Downloaded as one public JSON file and matched locally, so nothing about this system is sent.
- FIRST EPSS: probability that a CVE is exploited in the next 30 days. Looked up per CVE,
  so the CVE IDs are sent to api.first.org; callers should make this opt-in.
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .vulnscan import SEVERITIES

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_MAX_AGE = 24 * 3600
EPSS_BATCH = 100
USER_AGENT = "secrets-scanner (+https://github.com/NiloyBhattacharjee/secrets-scanner)"

Fetch = Callable[[str], bytes]


class IntelError(Exception):
    pass


def default_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / "secrets-scanner"


def _fetch(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


# --- KEV ---------------------------------------------------------------------

@dataclass
class KevCatalog:
    entries: dict[str, dict]
    version: str
    source: str               # "download" | "cache" | "stale-cache" | "file"
    age_hours: float | None = None


def parse_kev(doc: dict) -> dict[str, dict]:
    out = {}
    for v in doc.get("vulnerabilities") or []:
        cve = v.get("cveID")
        if not cve:
            continue
        out[cve] = {
            "name": v.get("vulnerabilityName", ""),
            "date_added": v.get("dateAdded"),
            "due_date": v.get("dueDate"),
            "required_action": v.get("requiredAction", ""),
            "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
        }
    return out


def _catalog(raw: bytes, source: str, age_hours: float | None) -> KevCatalog:
    try:
        doc = json.loads(raw)
    except ValueError as e:
        raise IntelError(f"KEV catalog is not valid JSON: {e}") from e
    return KevCatalog(parse_kev(doc), doc.get("catalogVersion", "unknown"), source, age_hours)


def load_kev(path: str | None = None, cache_dir: Path | None = None,
             max_age: int = KEV_MAX_AGE, fetch: Fetch = _fetch) -> KevCatalog:
    """Load KEV from an explicit file, a fresh cache, a new download, or (offline) a stale cache."""
    if path:
        try:
            return _catalog(Path(path).read_bytes(), "file", None)
        except OSError as e:
            raise IntelError(f"cannot read KEV file: {e}") from e

    cache = (cache_dir or default_cache_dir()) / "kev.json"
    age = time.time() - cache.stat().st_mtime if cache.exists() else None
    if age is not None and age <= max_age:
        return _catalog(cache.read_bytes(), "cache", age / 3600)

    try:
        raw = fetch(KEV_URL)
        catalog = _catalog(raw, "download", 0.0)
    except (OSError, IntelError) as e:
        if age is None:
            raise IntelError(f"could not download the KEV catalog and no cached copy exists: {e}") from e
        return _catalog(cache.read_bytes(), "stale-cache", age / 3600)
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(raw)
    except OSError:
        pass  # caching is best-effort
    return catalog


# --- EPSS --------------------------------------------------------------------

def fetch_epss(cves: list[str], fetch: Fetch = _fetch) -> dict[str, dict]:
    """EPSS score and percentile for each CVE (sent to api.first.org in batches)."""
    out = {}
    unique = sorted(set(cves))
    for i in range(0, len(unique), EPSS_BATCH):
        url = f"{EPSS_URL}?cve={','.join(unique[i:i + EPSS_BATCH])}"
        try:
            doc = json.loads(fetch(url))
        except (OSError, ValueError) as e:
            raise IntelError(f"EPSS lookup failed: {e}") from e
        for row in doc.get("data") or []:
            out[row["cve"]] = {"score": float(row["epss"]), "percentile": float(row["percentile"])}
    return out


# --- Enrichment --------------------------------------------------------------

def enrich(vulns: list[dict], kev: dict[str, dict] | None, epss: dict[str, dict] | None) -> None:
    """Tag each vulnerability with KEV/EPSS data, then sort: KEV first, then EPSS, then severity."""
    for v in vulns:
        v["kev"] = (kev or {}).get(v["id"])
        v["epss"] = (epss or {}).get(v["id"])
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    vulns.sort(key=lambda v: (
        v["kev"] is None,
        -(v["epss"]["score"] if v["epss"] else 0.0),
        rank.get(v["severity"], len(SEVERITIES)),
        v["fixed"] is None,
        v["id"] or "",
    ))
