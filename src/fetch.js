import http from 'node:http';
import https from 'node:https';
import { parseSetCookie, splitCookiesString } from './parse.js';

const UA = 'cookie-sentinel (+https://github.com/MrLouisWright/cookie-sentinel)';

function request(url, { headers = {}, timeout = 15000, insecure = false, method = 'GET' } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : u.protocol === 'http:' ? http : null;
    if (!mod) return reject(new Error(`Unsupported protocol: ${u.protocol}`));
    const req = mod.request(u, { method, headers: { 'user-agent': UA, accept: '*/*', ...headers }, rejectUnauthorized: !insecure }, (res) => {
      res.resume(); // we only need headers
      res.on('end', () => resolve(res));
      res.on('error', reject);
    });
    req.setTimeout(timeout, () => req.destroy(new Error(`Timed out after ${timeout} ms: ${url}`)));
    req.on('error', reject);
    req.end();
  });
}

/**
 * Fetch a URL following redirects; returns { url, finalUrl, hops: [{url,status,location,setCookie:[]}], observations }.
 * Cookies received along the way are replayed on later hops to the same host (simple jar) unless jar === false.
 */
export async function collect(url, { headers = {}, maxRedirects = 10, timeout, insecure, jar = true, method } = {}) {
  const hops = [];
  const observations = [];
  const store = new Map(); // host -> Map(name -> value)
  let current = url;
  for (let i = 0; i <= maxRedirects; i++) {
    const host = new URL(current).host;
    const h = { ...headers };
    if (jar && store.has(host) && store.get(host).size) {
      const ours = [...store.get(host)].map(([k, v]) => `${k}=${v}`).join('; ');
      const userCookie = Object.keys(h).find((k) => k.toLowerCase() === 'cookie');
      if (userCookie) h[userCookie] = `${h[userCookie]}; ${ours}`; else h.cookie = ours;
    }
    const res = await request(current, { headers: h, timeout, insecure, method });
    const setCookie = splitCookiesString(res.headers['set-cookie'] || []);
    const location = res.headers.location ? new URL(res.headers.location, current).href : undefined;
    hops.push({ url: current, status: res.statusCode, location, setCookie });
    for (const sc of setCookie) {
      const cookie = parseSetCookie(sc);
      if (!cookie) continue;
      observations.push({ cookie, url: current, status: res.statusCode, hop: i, source: url });
      if (!store.has(host)) store.set(host, new Map());
      store.get(host).set(cookie.name, cookie.value);
    }
    if (res.statusCode >= 300 && res.statusCode < 400 && location) { current = location; continue; }
    return { url, finalUrl: current, hops, observations };
  }
  throw new Error(`Too many redirects (>${maxRedirects}) starting at ${url}`);
}

/** Expand base URLs × paths into a de-duplicated target list. */
export function expandTargets(urls, paths = []) {
  const out = [];
  for (const u of urls) {
    const base = new URL(/^https?:\/\//i.test(u) ? u : `https://${u}`);
    out.push(base.href);
    for (const p of paths) out.push(new URL(p, base).href);
  }
  return [...new Set(out)];
}
