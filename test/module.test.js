import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

describe('dual ESM + CJS exports', () => {
  it('imports the ESM entry', async () => {
    const mod = await import(pathToFileURL(join(root, 'src/index.js')).href);
    assert.equal(typeof mod.auditSetCookies, 'function');
    assert.equal(typeof mod.classifyCookie, 'function');
    const report = mod.auditSetCookies(['a=1; Path=/'], { origin: 'https://example.com/' });
    assert.ok(report.cookies.length);
  });

  it('requires the CJS bundle', () => {
    const require = createRequire(pathToFileURL(join(root, 'package.json')));
    const mod = require(join(root, 'dist/index.cjs'));
    assert.equal(typeof mod.auditSetCookies, 'function');
    assert.equal(typeof mod.lookupOpenCookieDatabase, 'function');
  });

  it('resolves require via package.json exports', () => {
    const require = createRequire(pathToFileURL(join(root, 'package.json')));
    const mod = require('cookie-sentinel');
    assert.equal(typeof mod.auditUrls, 'function');
  });
});
