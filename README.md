# cookie-sentinel

[![CI](https://github.com/MrLouisWright/cookie-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/MrLouisWright/cookie-sentinel/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/cookie-sentinel.svg)](https://www.npmjs.com/package/cookie-sentinel)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/node/v/cookie-sentinel.svg)](https://www.npmjs.com/package/cookie-sentinel)

> Audit the cookies your site sets before attackers do.

`cookie-sentinel` fetches your pages (following every redirect), collects every `Set-Cookie` header from every hop and audits each cookie against modern browser rules and security best practice. Every finding comes with a severity and a **concrete fix**. It also audits raw `Set-Cookie` lines offline from a file or stdin.

**cookie-sentinel is the dedicated cookie authority** in the [sentinel](https://github.com/MrLouisWright) set — use [header-sentinel](https://github.com/MrLouisWright/header-sentinel) for HTTP security headers only (it keeps a minimal cookie presence check and points here for depth).

CLI, library and GitHub Action. Node.js 18+, **zero runtime dependencies**. Optional **Playwright** / **Puppeteer** peer dependencies for JavaScript-set cookies.

Tests live under [`test/`](test/) and run in [GitHub Actions CI](.github/workflows/ci.yml) (including `import` + `require` checks).

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

## Classification (Open Cookie Database)

Each cookie is classified **offline** against a bundled snapshot of the [Open Cookie Database](https://github.com/jkwakman/Open-Cookie-Database) (no network at runtime):

- **Party:** first-party vs third-party (from `Domain` / page host)
- **Purpose:** tracking vs essential (from OCDB category)
- **Vendor / category** when the name matches the catalogue

Refresh the snapshot when you maintain the package:

```bash
npm run update-ocdb
```

## Install and run

```bash
npx cookie-sentinel https://example.com
npx cookie-sentinel https://example.com -p /login -p /account --fail-on medium
npx cookie-sentinel https://app.example.com --crawl urls.txt          # URLs or paths, one per line
npx cookie-sentinel https://app.example.com --crawl-depth 2 --max-pages 40   # follow same-origin links
npx cookie-sentinel https://app.example.com/account -H "Cookie: session=…"   # audit logged-in pages
npx cookie-sentinel https://app.example.com --headers-file auth.json --cookies-file jar.txt
npx cookie-sentinel https://app.example.com --browser playwright      # optional peer dep
COOKIE_SENTINEL_BEARER=… npx cookie-sentinel https://api.example.com/me
curl -si https://example.com | npx cookie-sentinel --input -              # offline
npx cookie-sentinel --input set-cookies.txt --origin https://app.example.com -f sarif > cookies.sarif
```

### Options

| Option | Description |
|---|---|
| `<url…>` | URLs to fetch (`https://` assumed if no scheme). Redirects are followed and cookies from every hop are audited |
| `-p, --path <path>` | Extra path to fetch on every URL (repeatable) |
| `--crawl <file>` | File of URLs or paths, one per line (`#` comments allowed) |
| `--crawl-depth <n>` | Follow same-origin links up to depth `n` (0 = off) |
| `--max-pages <n>` | Cap when crawling (default 25) |
| `-H, --header "Name: value"` | Request header (repeatable), e.g. `Cookie` or `Authorization` |
| `--headers-file <file>` | JSON headers for scripted auth |
| `--cookies-file <file>` | Cookie jar file (JSON, `name=value` lines, or Netscape format) |
| `--bearer <token>` | `Authorization: Bearer` shortcut (or `COOKIE_SENTINEL_BEARER`) |
| `--browser <engine>` | `playwright` or `puppeteer` (optional peer dependencies) |
| `-i, --input <file\|->` | Audit raw `Set-Cookie` lines offline |
| `--origin <url>` | URL context for `--input` (default `https://example.com/`) |
| `-c, --config <file>` | JSON config (default `.cookie-sentinel.json` if present) |
| `-f, --format` | `text` (default), `json`, `sarif`, `markdown` |
| `--fail-on <sev>` | `critical`, `high` (default), `medium`, `low`, `info` or `none` |
| `--no-classify` | Skip Open Cookie Database enrichment |

**Exit codes:** `0` passed, `1` findings at or above `--fail-on`, `2` usage error or every target failed to fetch.

## Configuration

`.cookie-sentinel.json`:

```json
{
  "failOn": "medium",
  "urls": ["https://app.example.com"],
  "paths": ["/login", "/account"],
  "headers": { "Accept-Language": "en" },
  "headersFile": "staging-headers.json",
  "cookiesFile": "staging-cookies.txt",
  "login": {
    "url": "https://app.example.com/api/login",
    "method": "POST",
    "headers": { "Content-Type": "application/json" },
    "body": "{\"user\":\"ci\",\"pass\":\"…\"}",
    "expectStatus": 200
  },
  "crawl": { "maxDepth": 2, "maxPages": 30 },
  "browser": { "engine": "playwright" },
  "sessionPatterns": ["^acme_u$"],
  "severity": { "broad-path": "off" },
  "allow": [{ "rule": "*", "cookie": "_ga*", "reason": "analytics allowlist" }]
}
```

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write
jobs:
  cookies:
    runs-on: ubuntu-latest
    steps:
      - uses: MrLouisWright/cookie-sentinel@<sha>
        with:
          urls: https://staging.example.com
          paths: /login /account
          bearer: ${{ secrets.STAGING_TOKEN }}
          fail-on: medium
          args: --crawl-depth 1 --max-pages 20
          sarif: cookies.sarif
```

Releases are published to npm with **[provenance](https://docs.npmjs.com/generating-provenance-statements)** (see [release workflow](.github/workflows/release.yml)).

## Library

ESM and CommonJS:

```js
import { auditUrls, auditSetCookies, formatText, classifyCookie } from 'cookie-sentinel';
// const { auditUrls } = require('cookie-sentinel'); // Node 18+

const report = await auditUrls(['https://example.com'], {
  paths: ['/login'],
  crawl: { maxDepth: 1, maxPages: 10 },
  headers: { Cookie: 'sid=…' },
});
console.log(formatText(report, { failOn: 'high' }));
console.log(report.classificationSummary);
```

Build types locally: `npm run build` (generates `dist/index.cjs` and `dist/*.d.ts`).

## Support

If this project is useful to you, you can support its development with a donation: [Buy me a coffee](https://donate.stripe.com/aFa00lek3cvX4Ds2Fk9EI0b). It helps keep these tools maintained, documented and free for everyone.

## License

MIT © Louis Wright ([Louis Wright](https://github.com/MrLouisWright))
