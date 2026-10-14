import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer } from './helpers.js';
import { discoverPages, extractLinks } from '../src/crawl.js';
import { auditUrls } from '../src/index.js';

describe('multi-page crawl', () => {
  /** @type {{ server: import('node:http').Server, base: string }} */
  let srv;

  it('extracts same-origin links from HTML', async () => {
    srv = await startServer();
    const links = extractLinks('<a href="/about">x</a><a href="https://other.test/x">y</a>', srv.base);
    assert.deepEqual(links, [`${srv.base}/about`]);
  });

  it('discovers linked pages', async () => {
    const { urls } = await discoverPages([`${srv.base}/`], { maxDepth: 1, maxPages: 10, jar: false });
    assert.ok(urls.includes(`${srv.base}/about`));
  });

  it('auditUrls crawl collects cookies from discovered pages', async () => {
    const report = await auditUrls([srv.base], { crawl: { maxDepth: 1, maxPages: 5 }, config: { failOn: 'none' }, jar: false });
    const names = report.cookies.map((c) => c.name);
    assert.ok(names.includes('theme'));
    assert.ok(names.includes('about_seen'));
    assert.ok(report.crawl.discovered >= 2);
  });

  after(async () => { if (srv?.server) await new Promise((r) => srv.server.close(r)); });
});
