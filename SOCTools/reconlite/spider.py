"""spider.py - Breadth-first, same-origin crawl with a depth limit.

Enhancement: fingerprint() hashes the homepage and lists its <script src> URLs.
"""
from __future__ import annotations

import hashlib
from collections import deque
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from util import SafeClient, in_scope, normalize_url, same_origin

SKIP_SCHEMES = ("mailto:", "javascript:", "tel:", "data:")
SKIP_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".pdf",
                   ".zip", ".gz", ".mp3", ".mp4", ".woff", ".woff2", ".ttf")


def extract_links(html: str, page_url: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if not href or href.lower().startswith(SKIP_SCHEMES):
            continue
        absolute = urljoin(page_url, href)
        if urlparse(absolute).scheme not in ("http", "https"):
            continue
        absolute = normalize_url(absolute)
        if absolute not in links:
            links.append(absolute)
    return links


def crawl(client: SafeClient, start_url: str, max_depth: int = 1, max_pages: int = 50) -> dict:
    start = normalize_url(start_url)
    seen = {start}
    queue = deque([(start, 0)])
    pages, offsite = [], set()

    def enqueue(link: str, depth: int) -> None:
        if not same_origin(link, start) or not in_scope(link):
            offsite.add(link)
        elif link not in seen and not urlparse(link).path.lower().endswith(SKIP_EXTENSIONS):
            seen.add(link)
            queue.append((link, depth))

    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()
        page = {"url": url, "depth": depth}
        try:
            resp = client.get(url)
        except requests.RequestException as exc:
            page["error"] = str(exc)
            pages.append(page)
            continue

        ctype = resp.headers.get("Content-Type", "")
        page.update(status=resp.status_code, content_type=ctype, length=len(resp.content), links_found=0)

        if resp.is_redirect and resp.headers.get("Location"):
            target = normalize_url(urljoin(url, resp.headers["Location"]))
            page["redirect_to"] = target
            if depth < max_depth:
                enqueue(target, depth + 1)
        elif resp.status_code == 200 and "html" in ctype.lower():
            soup = BeautifulSoup(resp.text, "html.parser")
            if soup.title and soup.title.string:
                page["title"] = soup.title.string.strip()
            links = extract_links(resp.text, url)
            page["links_found"] = len(links)
            if depth < max_depth:
                for link in links:
                    enqueue(link, depth + 1)
        pages.append(page)

    return {
        "start_url": start,
        "max_depth": max_depth,
        "pages": pages,
        "offsite_links_skipped": sorted(offsite),
        "not_visited_due_to_page_limit": len(queue),
    }


def fingerprint(client: SafeClient, base_url: str, top_n: int = 10) -> dict:
    """Hash index.html and list the first top_n external script URLs."""
    url = normalize_url(base_url)
    resp = client.get(url)
    soup = BeautifulSoup(resp.text, "html.parser")
    scripts = []
    for tag in soup.find_all("script", src=True):
        src = normalize_url(urljoin(url, tag["src"].strip()))
        if src not in [s["src"] for s in scripts]:
            scripts.append({"src": src, "same_origin": same_origin(src, url),
                            "has_integrity": tag.has_attr("integrity")})
    return {
        "url": url,
        "status": resp.status_code,
        "size_bytes": len(resp.content),
        "sha256": hashlib.sha256(resp.content).hexdigest(),
        "title": soup.title.string.strip() if soup.title and soup.title.string else None,
        "script_src_count": len(scripts),
        "inline_script_count": len(soup.find_all("script", src=False)),
        "top_scripts": scripts[:top_n],
    }
