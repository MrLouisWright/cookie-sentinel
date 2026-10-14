import { collect, expandTargets } from './fetch.js';

const HREF_RE = /\bhref\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/gi;

/** Extract links from HTML. */
export function extractLinks(html, baseUrl, { sameOrigin = true } = {}) {
  const base = new URL(baseUrl);
  const out = new Set();
  let m;
  HREF_RE.lastIndex = 0;
  while ((m = HREF_RE.exec(html))) {
    const raw = m[2] || m[3] || m[4];
    if (!raw || raw.startsWith('#') || /^javascript:/i.test(raw) || /^mailto:/i.test(raw) || /^tel:/i.test(raw)) continue;
    try {
      const u = new URL(raw, base);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;
      if (sameOrigin && u.origin !== base.origin) continue;
      u.hash = '';
      out.add(u.href);
    } catch { /* ignore */ }
  }
  return [...out];
}

/**
 * Breadth-first crawl from seed URLs (same-origin by default).
 */
export async function discoverPages(seeds, {
  maxPages = 25,
  maxDepth = 2,
  sameOrigin = true,
  headers = {},
  timeout,
  insecure,
  maxRedirects,
  jar = true,
  concurrency = 4,
  allowPath,
  denyPath,
} = {}) {
  const allowRe = allowPath ? new RegExp(allowPath) : null;
  const denyRe = denyPath ? new RegExp(denyPath) : null;
  const seen = new Set();
  const queue = [...new Set(seeds)].map((url) => ({ url, depth: 0 }));
  const pages = [];
  const errors = [];

  const allowed = (url) => {
    try {
      const p = new URL(url).pathname;
      if (denyRe?.test(p)) return false;
      if (allowRe && !allowRe.test(p)) return false;
      return true;
    } catch { return false; }
  };

  while (queue.length && pages.length < maxPages) {
    const batch = [];
    while (queue.length && batch.length < concurrency && pages.length + batch.length < maxPages) {
      const item = queue.shift();
      if (!item || seen.has(item.url)) continue;
      seen.add(item.url);
      if (!allowed(item.url)) continue;
      batch.push(item);
    }
    if (!batch.length) break;

    await Promise.all(batch.map(async ({ url, depth }) => {
      try {
        const res = await collect(url, { headers, timeout, insecure, maxRedirects, jar, readBody: true });
        const html = res.html || '';
        const links = extractLinks(html, res.finalUrl || url, { sameOrigin });
        pages.push({ url: res.finalUrl || url, links });
        if (depth < maxDepth) {
          for (const link of links) {
            if (!seen.has(link)) queue.push({ url: link, depth: depth + 1 });
          }
        }
      } catch (e) {
        errors.push({ url, error: e.message });
      }
    }));
  }

  return { urls: pages.map((p) => p.url), pages, errors };
}

/** Seeds plus discovered pages, expanded with optional paths. */
export function mergeCrawlTargets(seeds, discoveredUrls, paths = []) {
  return expandTargets([...new Set([...seeds, ...discoveredUrls])], paths);
}
