import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

/** @typedef {'first-party'|'third-party'|'unknown'} CookieParty */
/** @typedef {'essential'|'tracking'|'unknown'} CookiePurpose */

const TRACKING = new Set(['Analytics', 'Marketing', 'Targeting', 'Advertising', 'Social Media', 'Personalization']);
const ESSENTIAL = new Set(['Functional', 'Necessary', 'Strictly Necessary', 'Security', 'Preferences', 'Unknown']);

let _index;
function loadIndex() {
  if (_index) return _index;
  const baseDir = typeof __dirname !== 'undefined' ? __dirname : dirname(fileURLToPath(import.meta.url));
  const path = join(baseDir, '../data/ocdb.json');
  const snapshot = JSON.parse(readFileSync(path, 'utf8'));
  /** @type {Map<string, Array<object>>} */
  const exact = new Map();
  /** @type {Array<object>} */
  const wildcards = [];
  for (const e of snapshot.entries) {
    const row = { ...e };
    if (e.wildcard) wildcards.push(row);
    else {
      const key = e.name.toLowerCase();
      if (!exact.has(key)) exact.set(key, []);
      exact.get(key).push(row);
    }
  }
  _index = { exact, wildcards, meta: { fetchedAt: snapshot.fetchedAt, entryCount: snapshot.entryCount } };
  return _index;
}

function matchWildcard(pattern, name) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`, 'i').test(name);
}

/** @returns {object|null} */
export function lookupOpenCookieDatabase(name) {
  const { exact, wildcards } = loadIndex();
  const hit = exact.get(String(name).toLowerCase());
  if (hit?.length) return hit[0];
  for (const row of wildcards) {
    if (matchWildcard(row.name, name)) return row;
  }
  return null;
}

/** Registrable domain approximation (good enough for audit classification). */
export function registrableDomain(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!h || h === 'localhost' || /^\d+\.\d+\.\d+\.\d+$/.test(h)) return h;
  const parts = h.split('.');
  if (parts.length <= 2) return h;
  const multi = new Set(['co.uk', 'org.uk', 'ac.uk', 'com.au', 'co.jp', 'com.br']);
  const tail2 = parts.slice(-2).join('.');
  if (multi.has(tail2) && parts.length >= 3) return parts.slice(-3).join('.');
  return tail2;
}

/** @param {string} pageUrl @param {string|undefined} cookieDomainAttr @param {object|null} ocdb */
export function cookieParty(pageUrl, cookieDomainAttr, ocdb) {
  if (ocdb?.domain?.includes('3rd party')) return 'third-party';
  let pageHost;
  try { pageHost = new URL(pageUrl).hostname; } catch { return 'unknown'; }
  const pageReg = registrableDomain(pageHost);
  const cookieHost = (cookieDomainAttr || pageHost).toLowerCase().replace(/^\./, '');
  const cookieReg = registrableDomain(cookieHost);
  if (!cookieReg || !pageReg) return 'unknown';
  if (cookieReg === pageReg) return 'first-party';
  if (pageHost.endsWith(cookieHost) || cookieHost.endsWith(pageReg)) return 'first-party';
  return 'third-party';
}

/** @param {string|undefined} category */
export function purposeFromCategory(category) {
  if (!category) return 'unknown';
  if (TRACKING.has(category)) return 'tracking';
  if (ESSENTIAL.has(category)) return 'essential';
  if (/analytic/i.test(category) || /market/i.test(category)) return 'tracking';
  if (/function/i.test(category) || /necess/i.test(category)) return 'essential';
  return 'unknown';
}

/**
 * Classify a cookie for privacy/consent reporting.
 * @param {{ name: string, attrs?: { domain?: string } }} cookie
 * @param {string} pageUrl
 */
export function classifyCookie(cookie, pageUrl) {
  const ocdb = lookupOpenCookieDatabase(cookie.name);
  const party = cookieParty(pageUrl, cookie.attrs?.domain, ocdb);
  const purpose = purposeFromCategory(ocdb?.category);
  return {
    party,
    purpose,
    category: ocdb?.category || null,
    vendor: ocdb?.vendor || null,
    retentionPeriod: ocdb?.retentionPeriod || null,
    openCookieDatabase: ocdb ? { name: ocdb.name, vendor: ocdb.vendor, category: ocdb.category } : null,
  };
}

export function databaseMeta() {
  return loadIndex().meta;
}
