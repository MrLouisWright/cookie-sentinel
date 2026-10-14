import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { startServer } from './helpers.js';
import { loadHeadersFile, loadCookiesFile, runLogin } from '../src/auth.js';
import { auditUrls } from '../src/index.js';

describe('scripted auth', () => {
  /** @type {{ server: import('node:http').Server, base: string }} */
  let srv;
  let dir;

  after(async () => { if (srv?.server) await new Promise((r) => srv.server.close(r)); });

  it('loads headers and cookies files', async () => {
    dir = mkdtempSync(join(tmpdir(), 'cs-auth-'));
    writeFileSync(join(dir, 'h.json'), JSON.stringify({ Authorization: 'Bearer x' }));
    writeFileSync(join(dir, 'c.txt'), 'sid=abc\nui=1');
    assert.equal(loadHeadersFile(join(dir, 'h.json')).Authorization, 'Bearer x');
    assert.match(loadCookiesFile(join(dir, 'c.txt')), /sid=abc/);
  });

  it('runs login step and audits protected pages', async () => {
    srv = await startServer();
    const { headers } = await runLogin({ url: `${srv.base}/auth`, method: 'POST', body: '', expectStatus: 200 }, {});
    assert.match(headers.Cookie || headers.cookie || '', /sid=good/);
    const report = await auditUrls([`${srv.base}/account`], { headers, config: { failOn: 'none' }, jar: false });
    assert.ok(report.cookies.some((c) => c.name === 'user_email'));
  });
});
