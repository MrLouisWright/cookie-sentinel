import test from 'node:test';
import assert from 'node:assert/strict';
import { collect, auditUrls, expandTargets } from '../src/index.js';
import { startServer } from './helpers.js';

let srv;
test.before(async () => { srv = await startServer(); });
test.after(() => srv.server.close());

test('follows redirects and records Set-Cookie from every hop, replaying the jar', async () => {
  const r = await collect(`${srv.base}/redirect`);
  assert.deepEqual(r.hops.map((h) => h.status), [302, 301, 200]);
  assert.deepEqual(r.observations.map((o) => [o.cookie.name, o.hop]), [['hop1', 0], ['auth_token', 1], ['jarseen', 2]]);
  assert.equal(r.observations[2].cookie.value, 'yes');
  const nojar = await collect(`${srv.base}/redirect`, { jar: false });
  assert.equal(nojar.observations[2].cookie.value, 'no');
});
test('redirect loops are bounded', async () => {
  await assert.rejects(collect(`${srv.base}/loop`, { maxRedirects: 3 }), /Too many redirects/);
});
test('multiple paths, auth headers and http findings', async () => {
  const anon = await auditUrls([srv.base], { paths: ['/login', '/account'] });
  assert.equal(anon.targets.length, 3);
  assert.ok(!anon.cookies.some((c) => c.name === 'user_email'));
  const r = await auditUrls([srv.base], { paths: ['/login', '/account'], headers: { Authorization: 'Bearer s3cret' } });
  const has = (rule, cookie) => r.findings.some((f) => f.rule === rule && f.cookie === cookie);
  assert.ok(has('sensitive-email', 'user_email'));
  assert.ok(has('missing-httponly', 'sessionid'));
  assert.ok(has('cookie-over-http', 'sessionid'));
  assert.ok(has('long-expiry', 'remember_me'));
  assert.ok(!r.findings.some((f) => f.cookie === 'csrftoken' && f.rule === 'missing-httponly'));
  const viaCookie = await auditUrls([`${srv.base}/account`], { headers: { Cookie: 'sid=good' } });
  assert.ok(viaCookie.cookies.some((c) => c.name === 'user_email'));
});
test('duplicates and big cookies from a live response; connection errors are reported', async () => {
  const r = await auditUrls([`${srv.base}/dupes`, `${srv.base}/big`, 'http://127.0.0.1:1/']);
  assert.ok(r.findings.some((f) => f.rule === 'duplicate-cookie' && f.cookie === 'a'));
  assert.ok(r.findings.some((f) => f.rule === 'large-cookie' && f.cookie === 'big'));
  assert.equal(r.errors.length, 1);
});
test('expandTargets dedupes and defaults to https', () => {
  assert.deepEqual(expandTargets(['example.com'], ['/a', 'a', '/']), ['https://example.com/', 'https://example.com/a']);
});
