"""dirs.py - Probe a tiny, safe path list and record status codes.

Enhancement: write_csv() exports the probe results to CSV.
"""
from __future__ import annotations

import csv
import hashlib
import re
import secrets
from pathlib import Path

import requests

from util import SafeClient, log, normalize_url

MAX_WORDLIST_ENTRIES = 50   # refuse anything that isn't a tiny wordlist
INTERESTING_STATUSES = {200, 204, 301, 302, 307, 308, 401, 403}
SAFE_ENTRY = re.compile(r"^[A-Za-z0-9._\-/]+$")
CSV_FIELDS = ["path", "url", "status", "length", "content_type", "location",
              "soft_404", "interesting", "error"]


def load_wordlist(path: str | Path) -> list[str]:
    entries = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        word = raw.strip().strip("/")
        if not word or word.startswith("#"):
            continue
        if ".." in word or not SAFE_ENTRY.match(word):
            log.warning("Skipping unsafe wordlist entry: %r", raw)
            continue
        if word not in entries:
            entries.append(word)
    if not entries:
        raise ValueError(f"wordlist {path} has no usable entries")
    if len(entries) > MAX_WORDLIST_ENTRIES:
        raise ValueError(f"wordlist has {len(entries)} entries; only tiny wordlists "
                         f"(at most {MAX_WORDLIST_ENTRIES}) are allowed")
    return entries


def _base_dir(base_url: str) -> str:
    url = normalize_url(base_url).split("?", 1)[0]
    return url if url.endswith("/") else url + "/"


def _baseline(client: SafeClient, base: str) -> dict | None:
    """Request one random path that shouldn't exist. Many single-page apps
    return 200 + index.html for every unknown path, so results that match this
    baseline are marked as soft 404s instead of real finds."""
    url = base + "reconlite-baseline-" + secrets.token_hex(6)
    try:
        resp = client.get(url)
    except requests.RequestException:
        return None
    return {"url": url, "status": resp.status_code, "length": len(resp.content),
            "sha256": hashlib.sha256(resp.content).hexdigest()}


def probe(client: SafeClient, base_url: str, words: list[str]) -> dict:
    base = _base_dir(base_url)
    baseline = _baseline(client, base)
    results = []
    for word in words:
        url = normalize_url(base + word)
        row = {"path": "/" + word, "url": url}
        try:
            resp = client.get(url)
        except requests.RequestException as exc:
            row.update(error=str(exc), soft_404=False, interesting=False)
            results.append(row)
            continue
        digest = hashlib.sha256(resp.content).hexdigest()
        soft = bool(baseline and resp.status_code == baseline["status"] and digest == baseline["sha256"])
        row.update(
            status=resp.status_code,
            length=len(resp.content),
            content_type=resp.headers.get("Content-Type", ""),
            location=resp.headers.get("Location"),
            soft_404=soft,
            interesting=resp.status_code in INTERESTING_STATUSES and not soft,
        )
        results.append(row)
    return {"base": base, "baseline": baseline, "results": results}


def write_csv(results: list[dict], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in results:
            writer.writerow({k: row.get(k, "") for k in CSV_FIELDS})
