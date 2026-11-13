"""robots.py - Retrieve and parse /robots.txt."""
from __future__ import annotations

from util import SafeClient, join_url

MAX_RAW_CHARS = 2000


def parse_robots(text: str) -> dict:
    user_agents, disallow, allow, sitemaps = [], [], [], []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        key = key.lower()
        if key == "user-agent" and value not in user_agents:
            user_agents.append(value)
        elif key == "disallow" and value and value not in disallow:
            disallow.append(value)
        elif key == "allow" and value and value not in allow:
            allow.append(value)
        elif key == "sitemap" and value not in sitemaps:
            sitemaps.append(value)
    return {"user_agents": user_agents, "disallow": disallow, "allow": allow, "sitemaps": sitemaps}


def fetch_robots(client: SafeClient, base_url: str) -> dict:
    url = join_url(base_url, "/robots.txt")
    resp = client.get(url)
    ctype = resp.headers.get("Content-Type", "")
    result = {"url": url, "status": resp.status_code, "content_type": ctype, "found": False}
    # Single-page apps often answer every path with index.html, so a 200 that
    # is HTML is not a real robots.txt.
    if resp.status_code == 200 and "html" not in ctype.lower():
        result["found"] = True
        result.update(parse_robots(resp.text))
        result["raw"] = resp.text[:MAX_RAW_CHARS]
    return result
