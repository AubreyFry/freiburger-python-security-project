"""cli.py - Argument parsing and orchestration for reconlite.

Run from inside the reconlite folder:
    python cli.py --target http://localhost:3000
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

import dirs
import headers
import robots
import spider
from rate import DEFAULT_MAX_REQUESTS, MIN_DELAY, RateLimiter, RequestCapReached
from util import (ALLOWED_HOSTS, BANNER, SafeClient, ScopeError, in_scope, log,
                  normalize_url, setup_logging)

VERSION = "1.0"
HERE = Path(__file__).resolve().parent
MAX_DEPTH = 3


# --------------------------------------------------------------------------- args

def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="reconlite",
        description=f"Modular web recon tool. {BANNER}",
    )
    p.add_argument("--target", default="http://localhost:3000",
                   help="Target URL; host must be localhost or 127.0.0.1 (default: %(default)s)")
    p.add_argument("--json-out", default="findings.json",
                   help="Path for the JSON findings file (default: %(default)s)")
    p.add_argument("--report-out", default="report.md",
                   help="Path for the Markdown report (default: %(default)s)")
    p.add_argument("--csv-out", default="dir_probe.csv",
                   help="Path for the directory probe CSV export (default: %(default)s)")
    p.add_argument("--wordlist", default=str(HERE / "wordlist.txt"),
                   help="Tiny path wordlist (default: wordlist.txt next to cli.py)")
    p.add_argument("--depth", type=int, default=1,
                   help=f"Spider depth, 0-{MAX_DEPTH} (default: %(default)s)")
    p.add_argument("--max-pages", type=int, default=50,
                   help="Maximum pages the spider visits (default: %(default)s)")
    p.add_argument("--delay", type=float, default=MIN_DELAY,
                   help=f"Seconds between requests, minimum {MIN_DELAY} (default: %(default)s)")
    p.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS,
                   help=f"Request cap for the whole run, 1-{DEFAULT_MAX_REQUESTS} (default: %(default)s)")
    p.add_argument("--timeout", type=float, default=5.0,
                   help="Per-request timeout in seconds (default: %(default)s)")
    p.add_argument("--top-scripts", type=int, default=10,
                   help="How many <script src> URLs to list in the fingerprint (default: %(default)s)")
    p.add_argument("-v", "--verbose", action="store_true", help="Show debug logging")
    args = p.parse_args(argv)

    if not 0 <= args.depth <= MAX_DEPTH:
        p.error(f"--depth must be between 0 and {MAX_DEPTH}")
    if args.max_pages < 1:
        p.error("--max-pages must be at least 1")
    if args.delay < MIN_DELAY:
        p.error(f"--delay must be at least {MIN_DELAY} seconds")
    if not 1 <= args.max_requests <= DEFAULT_MAX_REQUESTS:
        p.error(f"--max-requests must be between 1 and {DEFAULT_MAX_REQUESTS}")
    if args.timeout <= 0:
        p.error("--timeout must be positive")
    if args.top_scripts < 1:
        p.error("--top-scripts must be at least 1")
    return args


def print_banner() -> None:
    line = "=" * (len(BANNER) + 4)
    print(line)
    print(f"  reconlite v{VERSION}")
    print(f"  {BANNER}")
    print(line)


# ------------------------------------------------------------- recommendations

def build_recommendations(f: dict) -> list[str]:
    recs: list[str] = []

    def add(text: str) -> None:
        if text not in recs:
            recs.append(text)

    h = f.get("headers") or {}
    for item in h.get("missing", []):
        add(item["recommendation"])
    for item in h.get("weak", []):
        add(item["recommendation"])
    for item in h.get("info_leaks", []):
        add(f"Remove or genericize the {item['header']} header (currently '{item['value']}') "
            "so attackers can't easily look up known vulnerabilities for that software.")

    r = f.get("robots") or {}
    if r.get("disallow"):
        paths = ", ".join(r["disallow"])
        add(f"Don't rely on robots.txt to hide sensitive paths; it publicly lists {paths}. "
            "Protect those paths with authentication or remove them from the web root.")

    d = f.get("directories") or {}
    exposed = [row for row in d.get("results", []) if row.get("interesting") and row.get("status") in (200, 204)]
    if exposed:
        paths = ", ".join(row["path"] for row in exposed)
        add(f"Review the exposed paths ({paths}); put admin and backup content behind "
            "authentication or remove it from the web root.")

    fp = f.get("fingerprint") or {}
    scripts = fp.get("top_scripts", [])
    if scripts and not all(s["has_integrity"] for s in scripts):
        add("Add Subresource Integrity (integrity=\"sha384-...\") to <script> tags and monitor the "
            "homepage hash so unexpected changes to served code are detected.")

    add("Place a web application firewall (WAF) in front of the app and alert on bursts of "
        "requests to missing paths, which is what directory probing looks like in logs.")
    return recs


# ---------------------------------------------------------------------- report

def _cell(value, limit: int = 80) -> str:
    text = "" if value is None else str(value)
    text = text.replace("|", "\\|").replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _table(columns: list[str], rows: list[list], limit: int = 80) -> list[str]:
    out = ["| " + " | ".join(columns) + " |", "|" + "---|" * len(columns)]
    out += ["| " + " | ".join(_cell(c, limit) for c in row) + " |" for row in rows]
    return out


def render_report(f: dict) -> str:
    m = f["meta"]
    h = f.get("headers") or {}
    r = f.get("robots") or {}
    s = f.get("spider") or {}
    d = f.get("directories") or {}
    fp = f.get("fingerprint") or {}
    L: list[str] = []

    L += [f"# Recon Report: {m['target']}", "", f"> {BANNER}", ""]
    L += _table(["Item", "Value"], [
        ["Tool", f"reconlite v{m['tool_version']}"],
        ["Target", m["target"]],
        ["Started (UTC)", m["started_utc"]],
        ["Duration", f"{m['duration_seconds']} s"],
        ["Requests used", f"{m['requests_made']} / {m['max_requests']} (delay {m['delay_seconds']} s)"],
    ])

    # Key findings
    L += ["", "## Key findings", ""]
    if h:
        L.append(f"- **Missing security headers ({len(h['missing'])}):** "
                 + (", ".join(i["header"] for i in h["missing"]) or "none"))
        L.append(f"- **Weak header settings ({len(h['weak'])}):** "
                 + (", ".join(i["header"] for i in h["weak"]) or "none"))
        if h["info_leaks"]:
            L.append("- **Technology disclosure:** "
                     + ", ".join(f"{i['header']}: {i['value']}" for i in h["info_leaks"]))
    if r:
        L.append("- **robots.txt:** " + (f"disallows {', '.join(r.get('disallow', [])) or 'nothing'}"
                                        if r.get("found") else "not found"))
    if d:
        hits = [row for row in d["results"] if row.get("interesting")]
        L.append("- **Directory probe:** " + (", ".join(f"{x['path']} ({x['status']})" for x in hits)
                                              or "no paths stood out from the not-found baseline"))
    if fp:
        L.append(f"- **Homepage fingerprint:** SHA-256 `{fp['sha256'][:16]}...`, "
                 f"{fp['script_src_count']} script file(s) loaded")

    # 1. Headers
    if h:
        L += ["", "## 1. HTTP headers", "", f"Checked `{h['url']}` (status {h['status']}).", ""]
        L += ["### Missing security headers", ""]
        L += _table(["Header", "Recommendation"], [[i["header"], i["recommendation"]] for i in h["missing"]], limit=200) \
            if h["missing"] else ["None missing."]
        L += ["", "### Weak header settings", ""]
        L += _table(["Header", "Value", "Why it's weak"], [[i["header"], i["value"], i["reason"]] for i in h["weak"]], limit=200) \
            if h["weak"] else ["No weak settings detected."]
        L += ["", "### Technology disclosure", ""]
        L += _table(["Header", "Value", "Reveals version?"],
                    [[i["header"], i["value"], "yes" if i["reveals_version"] else "no"] for i in h["info_leaks"]]) \
            if h["info_leaks"] else ["No version-revealing headers found."]
        for note in h.get("notes", []):
            L += ["", f"_Note: {note}_"]

    # 2. robots.txt
    if r:
        L += ["", "## 2. robots.txt", ""]
        if r.get("found"):
            L.append(f"Found at `{r['url']}`.")
            L.append("")
            L.append("- Disallow: " + (", ".join(f"`{x}`" for x in r["disallow"]) or "none"))
            L.append("- Allow: " + (", ".join(f"`{x}`" for x in r["allow"]) or "none"))
            L.append("- Sitemaps: " + (", ".join(r["sitemaps"]) or "none"))
        else:
            L.append(f"No robots.txt found (status {r.get('status')}).")

    # 3. Spider
    if s:
        L += ["", f"## 3. Spider (depth {s['max_depth']})", ""]
        L += _table(["URL", "Depth", "Status", "Type", "Links"],
                    [[p["url"], p["depth"], p.get("status", "error"), p.get("content_type", ""),
                      p.get("links_found", "")] for p in s["pages"]])
        if s["offsite_links_skipped"]:
            L += ["", f"Skipped {len(s['offsite_links_skipped'])} off-site link(s) (out of scope)."]
        L += ["", "_Single-page apps like Juice Shop build most links with JavaScript, so a plain HTML "
                  "crawl finds few pages; the fingerprint below lists the scripts that load the app._"]

    # 4. Directories
    if d:
        L += ["", "## 4. Directory probe", ""]
        L += _table(["Path", "Status", "Length", "Note"],
                    [[x["path"], x.get("status", "error"), x.get("length", ""),
                      "matches not-found baseline (soft 404)" if x.get("soft_404")
                      else ("interesting" if x.get("interesting") else (x.get("error") or ""))]
                     for x in d["results"]])
        b = d.get("baseline")
        if b:
            L += ["", f"_Baseline: a random non-existent path returned status {b['status']} "
                      f"({b['length']} bytes). Results identical to it are treated as not found._"]

    # 5. Fingerprint
    if fp:
        L += ["", "## 5. Homepage fingerprint", ""]
        L.append(f"- URL: `{fp['url']}` (status {fp['status']}, {fp['size_bytes']} bytes)")
        L.append(f"- SHA-256: `{fp['sha256']}`")
        if fp.get("title"):
            L.append(f"- Title: {fp['title']}")
        L.append(f"- Script tags: {fp['script_src_count']} with src, {fp['inline_script_count']} inline")
        if fp["top_scripts"]:
            L += ["", f"Top {len(fp['top_scripts'])} script URLs:", ""]
            L += _table(["Script", "Same origin", "SRI"],
                        [[x["src"], "yes" if x["same_origin"] else "no",
                          "yes" if x["has_integrity"] else "no"] for x in fp["top_scripts"]])

    # 6. Recommendations
    L += ["", "## 6. Defensive recommendations", ""]
    L += [f"{i}. {rec}" for i, rec in enumerate(f["recommendations"], 1)]

    if f["errors"]:
        L += ["", "## Errors", ""]
        L += [f"- {e['module']}: {e['error']}" for e in f["errors"]]
    L.append("")
    return "\n".join(L)


# ------------------------------------------------------------------------ main

def _write(path: str, text: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def main(argv=None) -> int:
    print_banner()
    args = parse_args(argv)
    setup_logging(args.verbose)

    # Scope guard: refuse to run against anything but the allowlist.
    try:
        target = normalize_url(args.target)
    except ScopeError as exc:
        log.error("Refusing to run: %s", exc)
        return 2
    if not in_scope(target):
        log.error("Refusing to run: target %s is not on the allowlist (%s).",
                  target, ", ".join(sorted(ALLOWED_HOSTS)))
        return 2

    try:
        words = dirs.load_wordlist(args.wordlist)
    except (OSError, ValueError) as exc:
        log.error("Wordlist problem: %s", exc)
        return 2

    limiter = RateLimiter(delay=args.delay, max_requests=args.max_requests)
    client = SafeClient(limiter, timeout=args.timeout)
    started = time.monotonic()
    findings: dict = {
        "meta": {
            "tool": "reconlite", "tool_version": VERSION, "target": target,
            "started_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "delay_seconds": args.delay, "max_requests": args.max_requests,
            "spider_depth": args.depth, "wordlist": [f"/{w}" for w in words],
        },
        "headers": None, "robots": None, "spider": None,
        "fingerprint": None, "directories": None,
        "recommendations": [], "errors": [],
    }

    log.info("Target %s is in scope. Starting recon.", target)

    # Connectivity check doubles as the header module.
    try:
        findings["headers"] = headers.analyze(client, target)
    except requests.ConnectionError:
        log.error("Could not connect to %s. Is Juice Shop running? "
                  "(docker run --rm -p 3000:3000 bkimminich/juice-shop)", target)
        return 1
    except requests.RequestException as exc:
        findings["errors"].append({"module": "headers", "error": str(exc)})

    steps = [
        ("robots", lambda: robots.fetch_robots(client, target)),
        ("spider", lambda: spider.crawl(client, target, args.depth, args.max_pages)),
        ("fingerprint", lambda: spider.fingerprint(client, target, args.top_scripts)),
        ("directories", lambda: dirs.probe(client, target, words)),
    ]
    for name, step in steps:
        log.info("Running %s module...", name)
        try:
            findings[name] = step()
        except RequestCapReached as exc:
            log.warning("Stopping early: %s", exc)
            findings["errors"].append({"module": name, "error": str(exc)})
            break
        except (requests.RequestException, ScopeError) as exc:
            log.warning("%s module failed: %s", name, exc)
            findings["errors"].append({"module": name, "error": str(exc)})

    findings["meta"]["requests_made"] = limiter.count
    findings["meta"]["duration_seconds"] = round(time.monotonic() - started, 2)
    findings["recommendations"] = build_recommendations(findings)

    _write(args.json_out, json.dumps(findings, indent=2))
    _write(args.report_out, render_report(findings))
    if findings["directories"]:
        dirs.write_csv(findings["directories"]["results"], args.csv_out)

    log.info("Done: %d requests in %.1f s.", limiter.count, findings["meta"]["duration_seconds"])
    log.info("Wrote %s, %s%s", args.json_out, args.report_out,
             f", {args.csv_out}" if findings["directories"] else "")
    return 0


if __name__ == "__main__":
    sys.exit(main())
