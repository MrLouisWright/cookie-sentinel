# Changelog

## 1.1.0 — 2026-10-14

- **Multi-page crawl** with `--crawl-depth` / `--max-pages` (or `crawl` in config): follows same-origin links and audits cookies on every discovered page.
- **Scripted auth** via `--headers-file`, `--cookies-file`, and optional `login` step in config (POST/login URL before crawl or fetch).
- **Open Cookie Database** classification (first/third-party, tracking/essential) using a bundled offline snapshot; refresh with `npm run update-ocdb`.
- **Optional headless browser** mode (`--browser playwright|puppeteer`) to capture cookies set via JavaScript (peer dependencies, loaded dynamically).
- Dual **ESM + CJS** exports (`import` / `require`), TypeScript declarations generated from source (`npm run build`), CI checks for both.
- Release workflow publishes with **`npm publish --provenance`**.

## 1.0.0 — 2026-10-13

Initial release by Louis Wright.

- Fetch URLs, extra paths and crawl lists, following redirects and auditing `Set-Cookie` from every hop (with a cookie jar replayed across hops).
- Rules: missing Secure, cookies over HTTP, missing HttpOnly on session-like cookies, SameSite missing/None/None-without-Secure/invalid, `__Host-`/`__Secure-` prefix violations, broad or mismatched Domain, Path=/ on sensitive cookies, excessive lifetime, large cookies, JWTs (including `alg: none`) and emails in values, duplicate cookies, Partitioned misuse. Every finding includes a fix.
- Custom headers, `--bearer` and cookies for logged-in pages; offline audit of raw `Set-Cookie` lines or `curl -i` output from a file or stdin.
- Config file with allowlist, per-rule severity, session name patterns and thresholds.
- Text, JSON, SARIF 2.1.0 and Markdown output; `--fail-on`; exit codes 0/1/2.
- Composite GitHub Action with job summary.
