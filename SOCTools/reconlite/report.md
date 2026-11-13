# Recon Report: http://localhost:3000/

> For educational use on authorized local targets only.

| Item | Value |
|---|---|
| Tool | reconlite v1.0 |
| Target | http://localhost:3000/ |
| Started (UTC) | 2026-11-13 21:08:59 |
| Duration | 1.61 s |
| Requests used | 9 / 500 (delay 0.2 s) |

## Key findings

- **Missing security headers (4):** Content-Security-Policy, Strict-Transport-Security, Referrer-Policy, Permissions-Policy
- **Weak header settings (2):** Access-Control-Allow-Origin, Feature-Policy
- **robots.txt:** disallows /ftp
- **Directory probe:** /assets (301)
- **Homepage fingerprint:** SHA-256 `7a077ea089234d5f...`, 3 script file(s) loaded

## 1. HTTP headers

Checked `http://localhost:3000/` (status 200).

### Missing security headers

| Header | Recommendation |
|---|---|
| Content-Security-Policy | Add a Content-Security-Policy that limits where scripts, styles, and frames can load from. |
| Strict-Transport-Security | Serve the site over HTTPS and enable HSTS (Strict-Transport-Security) so browsers refuse plain HTTP. |
| Referrer-Policy | Set Referrer-Policy: strict-origin-when-cross-origin (or stricter) so full URLs don't leak to other sites. |
| Permissions-Policy | Set a Permissions-Policy that turns off browser features the site doesn't use (camera, microphone, geolocation). |

### Weak header settings

| Header | Value | Why it's weak |
|---|---|---|
| Access-Control-Allow-Origin | * | CORS is open to every website ('*'). |
| Feature-Policy | payment 'self' | Feature-Policy is the old, deprecated name and modern browsers ignore it. |

### Technology disclosure

No version-revealing headers found.

_Note: Target uses plain HTTP; browsers ignore HSTS over HTTP, so HSTS only matters once HTTPS is enabled._

## 2. robots.txt

Found at `http://localhost:3000/robots.txt`.

- Disallow: `/ftp`
- Allow: none
- Sitemaps: none

## 3. Spider (depth 1)

| URL | Depth | Status | Type | Links |
|---|---|---|---|---|
| http://localhost:3000/ | 0 | 200 | text/html; charset=UTF-8 | 0 |

_Single-page apps like Juice Shop build most links with JavaScript, so a plain HTML crawl finds few pages; the fingerprint below lists the scripts that load the app._

## 4. Directory probe

| Path | Status | Length | Note |
|---|---|---|---|
| /admin | 200 | 9984 | matches not-found baseline (soft 404) |
| /login | 200 | 9984 | matches not-found baseline (soft 404) |
| /backup | 200 | 9984 | matches not-found baseline (soft 404) |
| /assets | 301 | 156 | interesting |

_Baseline: a random non-existent path returned status 200 (9984 bytes). Results identical to it are treated as not found._

## 5. Homepage fingerprint

- URL: `http://localhost:3000/` (status 200, 9984 bytes)
- SHA-256: `7a077ea089234d5fb7e9f5775a384573ec97da96d8c74aaf230984fc723fe48b`
- Title: OWASP Juice Shop
- Script tags: 3 with src, 2 inline

Top 3 script URLs:

| Script | Same origin | SRI |
|---|---|---|
| http://localhost:3000/polyfills.js | yes | no |
| http://localhost:3000/scripts.js | yes | no |
| http://localhost:3000/main.js | yes | no |

## 6. Defensive recommendations

1. Add a Content-Security-Policy that limits where scripts, styles, and frames can load from.
2. Serve the site over HTTPS and enable HSTS (Strict-Transport-Security) so browsers refuse plain HTTP.
3. Set Referrer-Policy: strict-origin-when-cross-origin (or stricter) so full URLs don't leak to other sites.
4. Set a Permissions-Policy that turns off browser features the site doesn't use (camera, microphone, geolocation).
5. Limit Access-Control-Allow-Origin to the specific origins that need it.
6. Replace Feature-Policy with Permissions-Policy.
7. Don't rely on robots.txt to hide sensitive paths; it publicly lists /ftp. Protect those paths with authentication or remove them from the web root.
8. Add Subresource Integrity (integrity="sha384-...") to <script> tags and monitor the homepage hash so unexpected changes to served code are detected.
9. Place a web application firewall (WAF) in front of the app and alert on bursts of requests to missing paths, which is what directory probing looks like in logs.
