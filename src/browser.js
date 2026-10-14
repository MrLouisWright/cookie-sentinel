import { parseSetCookie } from './parse.js';

/** @typedef {'playwright'|'puppeteer'} BrowserEngine */

async function loadPlaywright() {
  try {
    return await import('playwright');
  } catch (e) {
    throw new Error('Playwright is not installed. Add it as a dev/peer dependency: npm i -D playwright');
  }
}

async function loadPuppeteer() {
  try {
    return await import('puppeteer');
  } catch (e) {
    throw new Error('Puppeteer is not installed. Add it as a dev/peer dependency: npm i -D puppeteer');
  }
}

function playwrightToObservation(c, pageUrl) {
  const parts = [`${c.name}=${c.value}`];
  if (c.domain) parts.push(`Domain=${c.domain}`);
  if (c.path) parts.push(`Path=${c.path}`);
  if (c.expires && c.expires > 0) parts.push(`Expires=${new Date(c.expires * 1000).toUTCString()}`);
  if (c.httpOnly) parts.push('HttpOnly');
  if (c.secure) parts.push('Secure');
  if (c.sameSite) parts.push(`SameSite=${c.sameSite}`);
  const raw = parts.join('; ');
  const cookie = parseSetCookie(raw);
  if (!cookie) return null;
  return { cookie, url: pageUrl, source: 'browser', via: 'playwright' };
}

function puppeteerToObservation(c, pageUrl) {
  const parts = [`${c.name}=${c.value}`];
  if (c.domain) parts.push(`Domain=${c.domain}`);
  if (c.path) parts.push(`Path=${c.path}`);
  if (c.expires && c.expires > 0) parts.push(`Expires=${new Date(c.expires * 1000).toUTCString()}`);
  if (c.httpOnly) parts.push('HttpOnly');
  if (c.secure) parts.push('Secure');
  if (c.sameSite && c.sameSite !== 'None') parts.push(`SameSite=${c.sameSite}`);
  else if (c.sameSite === 'None') parts.push('SameSite=None');
  const raw = parts.join('; ');
  const cookie = parseSetCookie(raw);
  if (!cookie) return null;
  return { cookie, url: pageUrl, source: 'browser', via: 'puppeteer' };
}

/**
 * Visit URLs in a headless browser and collect cookies (including HttpOnly and JS-set).
 * @param {string[]} urls
 * @param {{ engine?: BrowserEngine, headers?: Record<string,string>, timeout?: number, waitUntil?: string }} opts
 */
export async function collectBrowser(urls, { engine = 'playwright', headers = {}, timeout = 30000, waitUntil } = {}) {
  const observations = [];
  const targets = [];

  if (engine === 'puppeteer') {
    const puppeteer = await loadPuppeteer();
    const browser = await puppeteer.default.launch({ headless: true });
    try {
      const page = await browser.newPage();
      if (Object.keys(headers).length) await page.setExtraHTTPHeaders(headers);
      page.setDefaultNavigationTimeout(timeout);
      for (const url of urls) {
        const nav = await page.goto(url, { waitUntil: waitUntil || 'networkidle2' });
        const finalUrl = nav?.url() || url;
        const js = await page.evaluate(() => document.cookie).catch(() => '');
        for (const part of js.split(';').map((s) => s.trim()).filter(Boolean)) {
          const obs = parseSetCookie(part);
          if (obs) observations.push({ cookie: obs, url: finalUrl, source: 'browser-js', via: 'puppeteer' });
        }
        const cookies = await page.cookies(finalUrl);
        for (const c of cookies) {
          const o = puppeteerToObservation(c, finalUrl);
          if (o) observations.push(o);
        }
        targets.push({ url, finalUrl, engine: 'puppeteer' });
      }
    } finally {
      await browser.close();
    }
    return { observations: dedupeObservations(observations), targets };
  }

  const { chromium } = await loadPlaywright();
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({ extraHTTPHeaders: headers });
    context.setDefaultNavigationTimeout(timeout);
    const page = await context.newPage();
    for (const url of urls) {
      await page.goto(url, { waitUntil: waitUntil || 'networkidle' });
      const finalUrl = page.url();
      const js = await page.evaluate(() => document.cookie).catch(() => '');
      for (const part of js.split(';').map((s) => s.trim()).filter(Boolean)) {
        const obs = parseSetCookie(part);
        if (obs) observations.push({ cookie: obs, url: finalUrl, source: 'browser-js', via: 'playwright' });
      }
      const cookies = await context.cookies(finalUrl);
      for (const c of cookies) {
        const o = playwrightToObservation(c, finalUrl);
        if (o) observations.push(o);
      }
      targets.push({ url, finalUrl, engine: 'playwright' });
    }
  } finally {
    await browser.close();
  }
  return { observations: dedupeObservations(observations), targets };
}

function dedupeObservations(list) {
  const seen = new Set();
  const out = [];
  for (const o of list) {
    const k = `${o.url}\0${o.cookie.name}\0${o.cookie.raw}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(o);
  }
  return out;
}
