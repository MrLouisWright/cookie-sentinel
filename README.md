# cookie-sentinel

> Audit the cookies your site sets before attackers do.

`cookie-sentinel` fetches your pages (following every redirect), collects every `Set-Cookie` header from every hop and audits each cookie against modern browser rules and security best practice. Every finding comes with a severity and a **concrete fix**. It also audits raw `Set-Cookie` lines offline from a file or stdin.

CLI, library and GitHub Action. Node.js 18+, **zero runtime dependencies**.

## Rules

| Rule | Default severity | What it catches |
|---|---|---|
| `missing-secure` | high (session-like) / medium | Cookie on an HTTPS site without `Secure` |
| `cookie-over-http` | high (session-like) / medium | Cookie set by a plain `http://` response |
| `missing-httponly` | high | Session-like cookie (configurable name patterns) without `HttpOnly` |
| `samesite-missing` | medium (session-like) / low | No `SameSite` attribute |
| `samesite-none` | medium (session-like) / low | `SameSite=None` (cross-site sending, CSRF exposure) |
| `samesite-none-insecure` | high | `SameSite=None` without `Secure`: browsers reject it |
| `samesite-invalid` | medium | `SameSite` value that isn't Strict/Lax/None |
| `host-prefix` | high | `__Host-` cookie without `Secure`, with `Domain`, without `Path=/`, or set over HTTP; mis-cased prefixes |
| `secure-prefix` | high | `__Secure-` cookie without `Secure` or set over HTTP |
| `broad-domain` | medium (session-like) / low; high for a TLD | `Domain=` a parent domain (sent to and overwritable by every subdomain) or `Domain` on a session cookie |
| `domain-mismatch` | low | `Domain` that doesn't match the host (cookie rejected) |
| `broad-path` | info | Sensitive cookie with `Path=/` |
| `long-expiry` | medium (session-like > 30 days) / low (> 400 days) | Excessive `Expires`/`Max-Age` |
| `large-cookie` | low (> 3072 B) / medium (> 4096 B) | Very large cookies |
| `sensitive-jwt` | medium; high without HttpOnly | JWT in a cookie value (payload claims are readable) |
| `jwt-alg-none` | critical | Unsigned JWT (`alg: none`) |
| `sensitive-email` | medium | Email address in a value (plain, URL-encoded, base64 or JWT claims) |
| `duplicate-cookie` | low / medium | Same cookie set twice in one response, or one name set with different Domain/Path scopes (cookie tossing) |
| `partitioned-insecure` | high | `Partitioned` without `Secure` |
| `partitioned-misuse` | low | `Partitioned` without `SameSite=None`, or on session cookies |

Deletion cookies (`Max-Age<=0` or an expiry in the past) are ignored. Default session-like names include `sess`, `sid`, `auth`, `token`, `jwt`, `login`, `remember`, `access`, `refresh`, `PHPSESSID`, `JSESSIONID`, `connect.sid` and others. `csrf`/`xsrf` cookies are excluded from the HttpOnly check.

## Install and run

```bash
npx cookie-sentinel https://example.com
npx cookie-sentinel https://example.com -p /login -p /account --fail-on medium
npx cookie-sentinel https://app.example.com --crawl urls.txt          # URLs or paths, one per line
npx cookie-sentinel https://app.example.com/account -H "Cookie: session=…"   # audit logged-in pages
COOKIE_SENTINEL_BEARER=… npx cookie-sentinel https://api.example.com/me
curl -si https://example.com | npx cookie-sentinel --input -              # offline
npx cookie-sentinel --input set-cookies.txt --origin https://app.example.com -f sarif > cookies.sarif
```

### Sample output

```text
cookie-sentinel — 3 cookie(s) from 1 target(s)

__Host-csrf  https://app.example.com/
  HIGH     "__Host-csrf" violates the __Host- prefix rules (Path=/app (must be /)); browsers will reject it [host-prefix]
           ↳ fix: A __Host- cookie must have Secure, Path=/, no Domain and be set over HTTPS.

sid  https://app.example.com/
  HIGH     "sid" has no Secure attribute; it will be sent over plain HTTP if the user ever hits an http:// URL [missing-secure]
           ↳ fix: Add Secure: `Set-Cookie: sid=…; Secure`.
  HIGH     "sid" looks like a session/auth cookie but lacks HttpOnly, so any XSS can steal it via document.cookie [missing-httponly]
           ↳ fix: Add HttpOnly. If front-end code genuinely needs this value, allowlist it in the config (allow: [{ rule: "missing-httponly", cookie: "sid" }]).
  MEDIUM   "sid" has no SameSite attribute; behaviour depends on the browser default (Lax in Chromium, None in some others) [samesite-missing]
           ↳ fix: Set it explicitly: `SameSite=Lax` (or `Strict` for this session cookie).
  INFO     "sid" is a sensitive cookie sent to every path on app.example.com (Path=/) [broad-path]
           ↳ fix: If only part of the site needs it (e.g. /api or /admin), set a narrower Path. Note Path is not a security boundary against same-origin scripts.

remember_token  https://app.example.com/
  MEDIUM   "remember_token" is SameSite=None, so it is sent on cross-site requests (CSRF exposure for a session cookie) [samesite-none]
           ↳ fix: Use SameSite=Lax unless the cookie is genuinely needed in third-party/iframe contexts; if so, consider Partitioned (CHIPS).
  MEDIUM   "remember_token" has Domain=example.com, a parent of app.example.com, so every subdomain of example.com receives (and can overwrite) it [broad-domain]
           ↳ fix: Remove Domain to make it host-only (ideally rename to __Host-remember_token), or scope it to the narrowest host that needs it.
  MEDIUM   "remember_token" lives for 365 days (limit 30 for session-like cookies) [long-expiry]
           ↳ fix: Shorten the lifetime (hours to days for sessions) and rotate on use; prefer short-lived sessions with server-side refresh.
  MEDIUM   "remember_token" contains a JWT whose payload is readable by anyone holding the cookie (claims: sub, email) [sensitive-jwt]
           ↳ fix: JWT payloads are only base64-encoded, not encrypted. Keep PII out of the claims or use an opaque session id.
  MEDIUM   "remember_token" JWT payload contains an email address [sensitive-email]
           ↳ fix: Remove personal data from token claims; use an opaque user id.

3 high, 6 medium, 1 info
✖ Failing (fail-on: high).
```

### Options

| Option | Description |
|---|---|
| `<url…>` | URLs to fetch (`https://` assumed if no scheme). Redirects are followed and cookies from every hop are audited |
| `-p, --path <path>` | Extra path to fetch on every URL (repeatable) |
| `--crawl <file>` | File of URLs or paths, one per line (`#` comments allowed) |
| `-H, --header "Name: value"` | Request header (repeatable), e.g. `Cookie` or `Authorization` |
| `--bearer <token>` | `Authorization: Bearer` shortcut (or `COOKIE_SENTINEL_BEARER`) |
| `-i, --input <file\|->` | Audit raw `Set-Cookie` lines offline. Accepts `curl -i` output; `@ https://host/path` lines switch URL context and `---` separates responses |
| `--origin <url>` | URL context for `--input` (default `https://example.com/`) |
| `-c, --config <file>` | JSON config (default `.cookie-sentinel.json` if present) |
| `-f, --format` | `text` (default), `json`, `sarif`, `markdown` |
| `--json/--sarif/--markdown <file>` | Also write that format to a file |
| `--fail-on <sev>` | `critical`, `high` (default), `medium`, `low`, `info` or `none` |
| `--session-pattern <regex>` | Extra session-like cookie name pattern (repeatable) |
| `--max-redirects`, `--timeout`, `--insecure`, `--no-jar` | Fetch tuning. Cookies received are replayed on later hops unless `--no-jar` |
| `--list-rules` | List rules and default severities |

**Exit codes:** `0` passed, `1` findings at or above `--fail-on`, `2` usage error or every target failed to fetch.

## Configuration

`.cookie-sentinel.json`:

```json
{
  "failOn": "medium",
  "urls": ["https://app.example.com"],
  "paths": ["/login", "/account"],
  "headers": { "Accept-Language": "en" },
  "sessionPatterns": ["^acme_u$"],
  "notSessionPatterns": ["^analytics_"],
  "sessionMaxAgeDays": 14,
  "maxAgeDays": 400,
  "largeBytes": 3072,
  "severity": { "broad-path": "off", "samesite-none": "high" },
  "allow": [
    { "rule": "missing-httponly", "cookie": "ui_state", "reason": "read by the SPA" },
    { "rule": "*", "cookie": "_ga*", "url": "https://app.example.com/*" }
  ]
}
```

Allowlist entries match on `rule`, `cookie` and `url` (globs with `*`); a plain string matches a cookie name for every rule. Suppressed findings still appear under `suppressed` in JSON output.

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # only if you upload SARIF
jobs:
  cookies:
    runs-on: ubuntu-latest
    steps:
      - uses: MrLouisWright/cookie-sentinel@<sha> # v1
        with:
          urls: https://staging.example.com
          paths: /login /account
          bearer: ${{ secrets.STAGING_TOKEN }}
          fail-on: medium
          sarif: cookies.sarif
```

Inputs: `urls`, `paths`, `input`, `origin`, `fail-on`, `config`, `bearer`, `sarif`, `json`, `job-summary`, `args`. The Markdown report is written to the job summary.

## Library

```js
import { auditUrls, auditSetCookies, formatText } from 'cookie-sentinel';

const report = await auditUrls(['https://example.com'], { paths: ['/login'], headers: { Cookie: 'sid=…' } });
console.log(formatText(report, { failOn: 'high' }));

const offline = auditSetCookies(['sid=1; Path=/'], { origin: 'https://example.com/' });
```

## License

MIT © Louis Wright
