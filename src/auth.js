import { readFileSync } from 'node:fs';
import { collect } from './fetch.js';

/** Parse a JSON headers file: either a flat object or { headers: {...} }. */
export function loadHeadersFile(path) {
  const raw = JSON.parse(readFileSync(path, 'utf8'));
  if (raw && typeof raw === 'object' && raw.headers && typeof raw.headers === 'object') return { ...raw.headers };
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) return { ...raw };
  throw new Error('Headers file must be a JSON object of header names to values');
}

/**
 * Parse cookies from a file: JSON array/object, "name=value" lines, or Netscape cookie jar format.
 * Returns a single Cookie header value.
 */
export function loadCookiesFile(path) {
  const text = readFileSync(path, 'utf8').trim();
  if (!text) return '';
  if (text.startsWith('{') || text.startsWith('[')) {
    const parsed = JSON.parse(text);
    const pairs = [];
    if (Array.isArray(parsed)) {
      for (const c of parsed) {
        if (typeof c === 'string') pairs.push(c);
        else if (c && c.name) pairs.push(`${c.name}=${c.value ?? ''}`);
      }
    } else if (parsed && typeof parsed === 'object') {
      for (const [k, v] of Object.entries(parsed)) pairs.push(`${k}=${v}`);
    }
    return pairs.join('; ');
  }
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  const netscape = lines.some((l) => l.includes('\t'));
  if (netscape) {
    const pairs = [];
    for (const line of lines) {
      if (line.startsWith('#')) continue;
      const cols = line.split('\t');
      if (cols.length >= 7 && !/^TRUE$/i.test(cols[3])) continue; // skip expired / host-only quirks
      if (cols.length >= 7) pairs.push(`${cols[5]}=${cols[6]}`);
    }
    return pairs.join('; ');
  }
  return lines.map((l) => l.replace(/^cookie:\s*/i, '')).join('; ');
}

/** Merge Cookie header into a headers object. */
export function mergeCookieHeader(headers, cookieHeader) {
  if (!cookieHeader) return headers;
  const out = { ...headers };
  const existing = Object.keys(out).find((k) => k.toLowerCase() === 'cookie');
  if (existing) out[existing] = `${out[existing]}; ${cookieHeader}`;
  else out.Cookie = cookieHeader;
  return out;
}

/**
 * Optional scripted login before crawling/auditing.
 * @param {object} login - { url, method?, headers?, body?, expectStatus?, saveCookies? }
 * @param {object} fetchOpts - passed to collect()
 * @returns {Promise<{ headers: Record<string,string>, result: object }>}
 */
export async function runLogin(login, fetchOpts = {}) {
  if (!login?.url) throw new Error('login.url is required');
  const headers = { ...(login.headers || {}) };
  const result = await collect(login.url, {
    ...fetchOpts,
    headers,
    method: login.method || 'POST',
    body: login.body,
  });
  const expect = login.expectStatus ?? [200, 201, 204, 302, 303, 307, 308];
  const ok = Array.isArray(expect) ? expect.includes(result.hops.at(-1)?.status) : result.hops.at(-1)?.status === expect;
  if (!ok) {
    throw new Error(`Login to ${login.url} returned ${result.hops.at(-1)?.status}, expected ${JSON.stringify(expect)}`);
  }
  const jar = new Map();
  for (const hop of result.hops) {
    for (const sc of hop.setCookie || []) {
      const m = sc.match(/^([^=]+)=([^;]*)/);
      if (m) jar.set(m[1].trim(), m[2]);
    }
  }
  const cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
  return { headers: mergeCookieHeader(fetchOpts.headers || {}, cookie), result };
}
