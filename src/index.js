import { parseSetCookie, splitCookiesString, lifetimeSeconds } from './parse.js';
import { RULES, SEVERITIES, rank, runRules, compilePatterns, DEFAULT_SESSION_PATTERNS, DEFAULT_NOT_SESSION_PATTERNS, isSessionLike } from './rules.js';
import { collect, expandTargets } from './fetch.js';
import { discoverPages, mergeCrawlTargets } from './crawl.js';
import { loadHeadersFile, loadCookiesFile, mergeCookieHeader, runLogin } from './auth.js';
import { classifyCookie, lookupOpenCookieDatabase, databaseMeta } from './classify.js';
import { collectBrowser } from './browser.js';
export { formatText, formatJson, formatSarif, formatMarkdown } from './report.js';
export {
  parseSetCookie, splitCookiesString, lifetimeSeconds, RULES, SEVERITIES, collect, expandTargets, isSessionLike,
  discoverPages, mergeCrawlTargets, loadHeadersFile, loadCookiesFile, mergeCookieHeader, runLogin,
  classifyCookie, lookupOpenCookieDatabase, databaseMeta, collectBrowser,
};

export const DEFAULTS = { maxAgeDays: 400, sessionMaxAgeDays: 30, largeBytes: 3072, flagBroadPath: true, thirdParty: false };

export function resolveOptions(config = {}) {
  const sessionPatterns = [...(config.replaceSessionPatterns ? [] : DEFAULT_SESSION_PATTERNS), ...(config.sessionPatterns || [])];
  return {
    ...DEFAULTS,
    ...config,
    sessionRe: compilePatterns(sessionPatterns),
    notSessionRe: compilePatterns([...DEFAULT_NOT_SESSION_PATTERNS, ...(config.notSessionPatterns || [])]),
  };
}

function glob(pattern, value) {
  if (pattern === undefined) return true;
  const re = new RegExp('^' + String(pattern).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', 'i');
  return re.test(value ?? '');
}

/** Apply per-rule severity overrides ("off" disables) and the allowlist. */
export function applyConfig(findings, config = {}) {
  const sev = config.severity || config.rules || {};
  const allow = config.allow || config.allowlist || [];
  const out = [];
  const suppressed = [];
  for (const f of findings) {
    const o = sev[f.rule];
    if (o === 'off' || o === false) continue;
    const g = { ...f, severity: SEVERITIES.includes(o) ? o : f.severity };
    const hit = allow.find((a) => (typeof a === 'string' ? glob(a, g.cookie) : (glob(a.rule, g.rule) && glob(a.cookie, g.cookie) && glob(a.url, g.url))));
    if (hit) { suppressed.push({ ...g, allowedBy: hit.reason || hit }); continue; }
    out.push(g);
  }
  out.sort((a, b) => rank(a.severity) - rank(b.severity) || a.url.localeCompare(b.url) || a.cookie.localeCompare(b.cookie));
  return { findings: out, suppressed };
}

function enrichObservations(observations, config) {
  if (config.classify === false) return observations;
  return observations.map((o) => ({
    ...o,
    classification: classifyCookie(o.cookie, o.url),
  }));
}

/** Audit already-collected observations ([{cookie,url}]) and build a report. */
export function auditObservations(observations, config = {}, meta = {}) {
  const opts = resolveOptions(config);
  const enriched = enrichObservations(observations, config);
  const raw = runRules(enriched, opts);
  const { findings, suppressed } = applyConfig(raw, config);
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]));
  const cookies = enriched.map((o) => ({
    name: o.cookie.name,
    url: o.url,
    hop: o.hop,
    sessionLike: isSessionLike(o.cookie.name, opts),
    setCookie: o.cookie.raw,
    source: o.source,
    classification: o.classification,
  }));
  const classificationSummary = summarizeClassification(cookies);
  return {
    tool: 'cookie-sentinel',
    generatedAt: new Date(config.now ?? Date.now()).toISOString(),
    targets: meta.targets || [],
    crawl: meta.crawl,
    browser: meta.browser,
    openCookieDatabase: databaseMeta(),
    cookies,
    classificationSummary,
    findings,
    suppressed,
    counts,
    errors: meta.errors || [],
  };
}

function summarizeClassification(cookies) {
  const summary = { firstParty: 0, thirdParty: 0, unknownParty: 0, essential: 0, tracking: 0, unknownPurpose: 0, catalogued: 0 };
  for (const c of cookies) {
    const cl = c.classification;
    if (!cl) continue;
    if (cl.party === 'first-party') summary.firstParty++;
    else if (cl.party === 'third-party') summary.thirdParty++;
    else summary.unknownParty++;
    if (cl.purpose === 'essential') summary.essential++;
    else if (cl.purpose === 'tracking') summary.tracking++;
    else summary.unknownPurpose++;
    if (cl.openCookieDatabase) summary.catalogued++;
  }
  return summary;
}

/** Audit raw Set-Cookie header lines (offline). `origin` gives the URL context. */
export function auditSetCookies(input, { origin = 'https://example.com/', config = {} } = {}) {
  const lines = Array.isArray(input) ? input : String(input).split(/\r?\n/);
  const observations = [];
  let url = origin;
  let response = 0;
  for (const line of lines) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const m = t.match(/^@\s*(\S+)/);
    if (m) { url = new URL(m[1], url).href; response++; continue; }
    if (/^---+$/.test(t)) { response++; continue; }
    for (const sc of splitCookiesString(t.replace(/^set-cookie\s*:\s*/i, ''))) {
      const cookie = parseSetCookie(sc);
      if (cookie) observations.push({ cookie, url, response });
    }
  }
  return auditObservations(observations, config, { targets: [{ url: origin, offline: true }] });
}

async function resolveRequestHeaders(config = {}, cliHeaders = {}) {
  let headers = { ...(config.headers || {}), ...cliHeaders };
  if (config.headersFile) headers = { ...loadHeadersFile(config.headersFile), ...headers };
  if (config.cookiesFile) headers = mergeCookieHeader(headers, loadCookiesFile(config.cookiesFile));
  if (config.login) {
    const { headers: afterLogin } = await runLogin(config.login, { headers, ...config.loginFetch });
    headers = afterLogin;
  }
  return headers;
}

/** Fetch URLs (× paths), optional multi-page crawl and headless browser capture. */
export async function auditUrls(urls, {
  paths = [],
  headers: headerOverrides = {},
  config = {},
  maxRedirects,
  timeout,
  insecure,
  jar,
  concurrency = 4,
  crawl,
  browser,
} = {}) {
  const headers = await resolveRequestHeaders(config, headerOverrides);
  let seeds = expandTargets(urls, paths);
  let crawlMeta;
  const crawlOpts = crawl ?? config.crawl;
  if (crawlOpts && crawlOpts.enabled !== false) {
    const discovered = await discoverPages(seeds, {
      maxPages: crawlOpts.maxPages ?? 25,
      maxDepth: crawlOpts.maxDepth ?? 2,
      sameOrigin: crawlOpts.sameOrigin !== false,
      headers,
      timeout: crawlOpts.timeout ?? timeout,
      insecure: crawlOpts.insecure ?? insecure,
      maxRedirects: crawlOpts.maxRedirects ?? maxRedirects,
      jar: crawlOpts.jar ?? jar,
      concurrency: crawlOpts.concurrency ?? concurrency,
      allowPath: crawlOpts.allowPath,
      denyPath: crawlOpts.denyPath,
    });
    seeds = mergeCrawlTargets(urls, discovered.urls, paths);
    crawlMeta = { seeds: urls.length, discovered: discovered.urls.length, maxPages: crawlOpts.maxPages ?? 25, errors: discovered.errors };
  }

  const browserOpts = browser ?? config.browser;
  let browserMeta;
  let browserObservations = [];
  if (browserOpts && browserOpts.engine) {
    const { observations, targets } = await collectBrowser(seeds, {
      engine: browserOpts.engine,
      headers,
      timeout: browserOpts.timeout ?? timeout,
      waitUntil: browserOpts.waitUntil,
    });
    browserObservations = observations;
    browserMeta = { engine: browserOpts.engine, pages: targets.length, cookies: observations.length };
  }

  const targets = seeds;
  const results = new Array(targets.length);
  let next = 0;
  const worker = async () => {
    while (next < targets.length) {
      const i = next++;
      try { results[i] = await collect(targets[i], { headers, maxRedirects, timeout, insecure, jar }); }
      catch (e) { results[i] = { url: targets[i], error: e.message }; }
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, targets.length) }, worker));
  const observations = [...results.flatMap((r) => r.observations || []), ...browserObservations];
  const errors = [
    ...(crawlMeta?.errors || []),
    ...results.filter((r) => r.error).map((r) => ({ url: r.url, error: r.error })),
  ];
  const tmeta = results.map((r) => (r.error ? { url: r.url, error: r.error } : { url: r.url, finalUrl: r.finalUrl, hops: r.hops.map((h) => ({ url: h.url, status: h.status, location: h.location, cookies: h.setCookie.length })) }));
  return auditObservations(observations, config, { targets: tmeta, errors, crawl: crawlMeta, browser: browserMeta });
}

export function exceeds(report, failOn = 'high') {
  if (failOn === 'none') return false;
  return report.findings.some((f) => rank(f.severity) <= rank(failOn));
}
