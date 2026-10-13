import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import https from 'node:https';
import { startServer } from './helpers.js';

const BIN = new URL('../bin/cookie-sentinel.js', import.meta.url).pathname;
const run = (args, input) => new Promise((resolve) => {
  const p = spawn(process.execPath, [BIN, ...args], { env: { ...process.env, NO_COLOR: '1' } });
  let out = '', err = '';
  p.stdout.on('data', (d) => (out += d)); p.stderr.on('data', (d) => (err += d));
  p.on('close', (code) => resolve({ code, out, err }));
  p.stdin.end(input ?? '');
});
let srv; const dir = mkdtempSync(join(tmpdir(), 'cs-'));
test.before(async () => { srv = await startServer(); });
test.after(() => srv.server.close());

test('exit 0 when clean, 1 on findings, 2 on usage/fetch errors', async () => {
  assert.equal((await run([`${srv.base}/clean`])).code, 0);
  const bad = await run([`${srv.base}/login`]);
  assert.equal(bad.code, 1); assert.match(bad.out, /missing-httponly/); assert.match(bad.out, /Failing/);
  assert.equal((await run([])).code, 2);
  assert.equal((await run(['--fail-on', 'bogus', srv.base])).code, 2);
  assert.equal((await run(['http://127.0.0.1:1/'])).code, 2);
  assert.equal((await run(['-H', 'nocolon', srv.base])).code, 2);
});
test('--fail-on controls the exit code', async () => {
  assert.equal((await run([srv.base, '--fail-on', 'high'])).code, 0); // theme: http + low findings only
  assert.equal((await run([srv.base, '--fail-on', 'medium'])).code, 1);
  assert.equal((await run([`${srv.base}/login`, '--fail-on', 'none'])).code, 0);
});
test('--header and --bearer reach logged-in pages; --path and --crawl', async () => {
  const h = await run([srv.base, '-p', '/account', '-H', 'Authorization: Bearer s3cret', '-f', 'json']);
  assert.ok(JSON.parse(h.out).cookies.some((c) => c.name === 'user_email'));
  const b = await run([`${srv.base}/account`, '--bearer', 's3cret', '-f', 'json']);
  assert.ok(JSON.parse(b.out).cookies.some((c) => c.name === 'remember_me'));
  const crawl = join(dir, 'crawl.txt'); writeFileSync(crawl, `# list\n/login\n/redirect\n${srv.base}/dupes\n`);
  const c = JSON.parse((await run([srv.base, '--crawl', crawl, '-f', 'json'])).out);
  assert.equal(c.targets.length, 4);
  assert.ok(c.cookies.some((x) => x.name === 'auth_token' && x.hop === 1));
});
test('offline input from stdin, file and raw curl -i output', async () => {
  const s = await run(['-i', '-', '--origin', 'https://a.example.com', '-f', 'json'], 'Set-Cookie: sid=1; Path=/\n');
  const j = JSON.parse(s.out); assert.equal(s.code, 1);
  assert.ok(j.findings.some((f) => f.rule === 'missing-secure'));
  const f = join(dir, 'curl.txt');
  writeFileSync(f, 'HTTP/2 200\ncontent-type: text/html\nset-cookie: __Host-s=1; Secure; HttpOnly; Path=/; SameSite=Strict\nset-cookie: pref=x; Secure; SameSite=Lax\n\n');
  const r = await run(['--input', f, '--fail-on', 'info', '--config', writeCfg({ flagBroadPath: false })]);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /2 cookie\(s\)/);
});
function writeCfg(obj) { const p = join(dir, `cfg-${Math.random()}.json`); writeFileSync(p, JSON.stringify(obj)); return p; }
test('config allowlist + severity and .cookie-sentinel.json', async () => {
  const cfg = writeCfg({ allow: [{ rule: 'missing-httponly', cookie: 'sessionid' }], severity: { 'cookie-over-http': 'off', 'samesite-missing': 'off', 'broad-path': 'off' } });
  const r = await run([`${srv.base}/login`, '--config', cfg, '--fail-on', 'info']);
  assert.equal(r.code, 0, r.out); assert.match(r.out, /suppressed by allowlist/);
  assert.equal((await run(['--config', join(dir, 'missing.json'), srv.base])).code, 2);
});
test('json, sarif and markdown outputs (stdout and files)', async () => {
  const sarif = join(dir, 'o.sarif'), json = join(dir, 'o.json'), md = join(dir, 'o.md');
  const r = await run([`${srv.base}/login`, '-f', 'sarif', '--json', json, '--sarif', sarif, '--markdown', md]);
  const s = JSON.parse(r.out);
  assert.equal(s.version, '2.1.0'); assert.ok(s.runs[0].results.length > 0);
  assert.ok(s.runs[0].results.every((x) => s.runs[0].tool.driver.rules[x.ruleIndex].id === x.ruleId));
  assert.deepEqual(JSON.parse(readFileSync(sarif, 'utf8')), s);
  assert.ok(JSON.parse(readFileSync(json, 'utf8')).findings.length);
  assert.match(readFileSync(md, 'utf8'), /\| Severity \| Cookie/);
  const m = await run([`${srv.base}/login`, '-f', 'markdown']); assert.match(m.out, /❌ Failing/);
});
test('--help, --version, --list-rules', async () => {
  assert.match((await run(['--help'])).out, /Exit codes/);
  assert.match((await run(['--version'])).out, /^\d+\.\d+\.\d+/);
  assert.match((await run(['--list-rules'])).out, /samesite-none-insecure/);
});
test('https with self-signed cert: Secure checks apply; --insecure needed', async (t) => {
  try { execFileSync('openssl', ['version']); } catch { return t.skip('openssl not available'); }
  const key = join(dir, 'k.pem'), cert = join(dir, 'c.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=localhost'], { stdio: 'ignore' });
  if (!existsSync(cert)) return t.skip('cert generation failed');
  const s = https.createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (req, res) => {
    res.setHeader('Set-Cookie', ['sid=1; HttpOnly; SameSite=Lax', '__Host-ok=1; Secure; HttpOnly; Path=/; SameSite=Strict']); res.end();
  });
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const url = `https://127.0.0.1:${s.address().port}/`;
  try {
    assert.equal((await run([url])).code, 2); // TLS rejected
    const r = await run([url, '--insecure', '-f', 'json']);
    const j = JSON.parse(r.out);
    assert.ok(j.findings.some((f) => f.rule === 'missing-secure' && f.cookie === 'sid' && f.severity === 'high'));
    assert.ok(!j.findings.some((f) => f.cookie === '__Host-ok' && f.rule !== 'broad-path'));
  } finally { s.close(); }
});
