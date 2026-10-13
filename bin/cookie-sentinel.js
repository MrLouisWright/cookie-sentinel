#!/usr/bin/env node
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { auditUrls, auditSetCookies, exceeds, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, RULES } from '../src/index.js';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const HELP = `cookie-sentinel ${pkg.version} — audit Set-Cookie headers for security issues

Usage:
  cookie-sentinel <url...> [options]
  cookie-sentinel --input cookies.txt [--origin https://app.example.com]
  curl -sI https://example.com | cookie-sentinel --input -

Options:
  -p, --path <path>         Extra path to fetch on each URL (repeatable), e.g. --path /login
      --crawl <file>        File with URLs or paths, one per line (paths resolve against each URL)
  -H, --header <h>          Request header "Name: value" (repeatable), e.g. -H "Cookie: sid=..."
      --bearer <token>      Shortcut for -H "Authorization: Bearer <token>" (or env COOKIE_SENTINEL_BEARER)
  -i, --input <file|->      Audit raw Set-Cookie lines from a file or stdin (offline, no requests)
      --origin <url>        URL context for --input (default https://example.com/)
  -c, --config <file>       JSON config (default: .cookie-sentinel.json if present)
  -f, --format <fmt>        text (default), json, sarif, markdown
      --json <file>         Also write JSON to file
      --sarif <file>        Also write SARIF to file
      --markdown <file>     Also write Markdown to file
      --fail-on <sev>       critical | high (default) | medium | low | info | none
      --session-pattern <re> Extra regex for session-like cookie names (repeatable)
      --max-redirects <n>   Default 10
      --timeout <ms>        Per-request timeout, default 15000
      --insecure            Accept invalid TLS certificates
      --no-jar              Do not replay received cookies on later redirect hops
      --list-rules          Print rules and default severities
      --no-color            Disable colours
  -v, --version / -h, --help

Exit codes: 0 = passed, 1 = findings at or above --fail-on, 2 = usage or fetch error.`;

function main() {
  let a;
  try {
    a = parseArgs({
      allowPositionals: true,
      options: {
        path: { type: 'string', short: 'p', multiple: true }, crawl: { type: 'string' },
        header: { type: 'string', short: 'H', multiple: true }, bearer: { type: 'string' },
        input: { type: 'string', short: 'i' }, origin: { type: 'string' },
        config: { type: 'string', short: 'c' }, format: { type: 'string', short: 'f' },
        json: { type: 'string' }, sarif: { type: 'string' }, markdown: { type: 'string' },
        'fail-on': { type: 'string' }, 'session-pattern': { type: 'string', multiple: true },
        'max-redirects': { type: 'string' }, timeout: { type: 'string' }, insecure: { type: 'boolean' },
        'no-jar': { type: 'boolean' }, 'list-rules': { type: 'boolean' }, 'no-color': { type: 'boolean' },
        version: { type: 'boolean', short: 'v' }, help: { type: 'boolean', short: 'h' },
      },
    });
  } catch (e) { return usage(e.message); }
  const { values: o, positionals } = a;
  if (o.help) { process.stdout.write(HELP + '\n'); return 0; }
  if (o.version) { process.stdout.write(pkg.version + '\n'); return 0; }
  if (o['list-rules']) { for (const [id, r] of Object.entries(RULES)) process.stdout.write(`${id.padEnd(24)} ${r.severity.padEnd(9)} ${r.title}\n`); return 0; }

  let config = {};
  const cfgPath = o.config || (existsSync('.cookie-sentinel.json') ? '.cookie-sentinel.json' : null);
  if (cfgPath) { try { config = JSON.parse(readFileSync(cfgPath, 'utf8')); } catch (e) { return usage(`Cannot read config ${cfgPath}: ${e.message}`); } }
  if (o['session-pattern']) config.sessionPatterns = [...(config.sessionPatterns || []), ...o['session-pattern']];
  try { for (const p of config.sessionPatterns || []) new RegExp(p); } catch (e) { return usage(`Invalid session pattern: ${e.message}`); }
  const failOn = o['fail-on'] || config.failOn || 'high';
  if (failOn !== 'none' && !SEVERITIES.includes(failOn)) return usage(`Invalid --fail-on: ${failOn}`);
  const format = o.format || 'text';
  if (!['text', 'json', 'sarif', 'markdown'].includes(format)) return usage(`Invalid --format: ${format}`);

  const headers = { ...(config.headers || {}) };
  for (const h of o.header || []) {
    const i = h.indexOf(':');
    if (i < 1) return usage(`Invalid --header "${h}" (expected "Name: value")`);
    headers[h.slice(0, i).trim()] = h.slice(i + 1).trim();
  }
  const bearer = o.bearer || process.env.COOKIE_SENTINEL_BEARER;
  if (bearer) headers.Authorization = `Bearer ${bearer}`;

  const finish = (report) => {
    const color = !o['no-color'] && process.stdout.isTTY && !process.env.NO_COLOR;
    const out = { text: () => formatText(report, { color, failOn }), json: () => formatJson(report), sarif: () => formatSarif(report, { version: pkg.version }), markdown: () => formatMarkdown(report, { failOn }) };
    process.stdout.write(out[format]());
    if (o.json) writeFileSync(o.json, formatJson(report));
    if (o.sarif) writeFileSync(o.sarif, formatSarif(report, { version: pkg.version }));
    if (o.markdown) writeFileSync(o.markdown, formatMarkdown(report, { failOn }));
    if (report.errors.length && !report.cookies.length) return 2;
    if (exceeds(report, failOn)) return 1;
    return report.errors.length ? 2 : 0;
  };

  if (o.input) {
    let text;
    try { text = readFileSync(o.input === '-' ? 0 : o.input, 'utf8'); } catch (e) { return usage(`Cannot read ${o.input}: ${e.message}`); }
    // Accept raw "curl -i" output: keep only Set-Cookie lines if headers are present.
    const lines = text.split(/\r?\n/);
    const looksLikeHeaders = lines.some((l) => /^HTTP\/\d/.test(l) || /^[\w-]+:\s/.test(l) && !/^set-cookie:/i.test(l));
    const kept = looksLikeHeaders ? lines.filter((l) => /^set-cookie:/i.test(l.trim()) || /^HTTP\/\d/.test(l) || /^@/.test(l)).map((l) => (/^HTTP\//.test(l) ? '---' : l)) : lines;
    let origin = o.origin || config.origin || 'https://example.com/';
    try { new URL(origin); } catch { return usage(`Invalid --origin ${origin}`); }
    return finish(auditSetCookies(kept, { origin, config }));
  }

  const urls = [...positionals, ...(config.urls || [])];
  const paths = [...(o.path || []), ...(config.paths || [])];
  if (o.crawl) {
    let list;
    try { list = readFileSync(o.crawl === '-' ? 0 : o.crawl, 'utf8'); } catch (e) { return usage(`Cannot read ${o.crawl}: ${e.message}`); }
    for (const l of list.split(/\r?\n/).map((x) => x.trim()).filter((x) => x && !x.startsWith('#'))) (/^https?:\/\//i.test(l) ? urls : paths).push(l);
  }
  if (!urls.length) return usage('No URL given (or use --input for offline Set-Cookie checks)');
  try { for (const u of urls) new URL(/^https?:\/\//i.test(u) ? u : `https://${u}`); } catch (e) { return usage(e.message); }
  return auditUrls(urls, {
    paths, headers, config,
    maxRedirects: o['max-redirects'] ? Number(o['max-redirects']) : undefined,
    timeout: o.timeout ? Number(o.timeout) : undefined,
    insecure: !!o.insecure || !!config.insecure, jar: !o['no-jar'],
  }).then(finish);
}

function usage(msg) { process.stderr.write(`cookie-sentinel: ${msg}\nRun with --help for usage.\n`); return 2; }

Promise.resolve().then(main).then((code) => { process.exitCode = code; }, (e) => { process.stderr.write(`cookie-sentinel: ${e.stack || e}\n`); process.exitCode = 2; });
