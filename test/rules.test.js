import test from 'node:test';
import assert from 'node:assert/strict';
import { auditSetCookies, exceeds } from '../src/index.js';

const NOW = Date.parse('2026-10-13T12:00:00Z');
const audit = (lines, origin = 'https://app.example.com/', config = {}) => auditSetCookies(lines, { origin, config: { now: NOW, ...config } });
const rules = (r, cookie) => r.findings.filter((f) => !cookie || f.cookie === cookie).map((f) => f.rule).sort();
const find = (r, rule, cookie) => r.findings.find((f) => f.rule === rule && (!cookie || f.cookie === cookie));

test('a hardened session cookie is clean', () => {
  const r = audit(['__Host-session=opaque123; Secure; HttpOnly; Path=/; SameSite=Lax; Max-Age=3600'], 'https://app.example.com/', { flagBroadPath: false });
  assert.deepEqual(r.findings, []);
  assert.equal(exceeds(r, 'info'), false);
});
test('missing Secure on https; session-like is high, others medium; not flagged on http', () => {
  const r = audit(['sid=1; HttpOnly; SameSite=Lax', 'pref=1; SameSite=Lax']);
  assert.equal(find(r, 'missing-secure', 'sid').severity, 'high');
  assert.equal(find(r, 'missing-secure', 'pref').severity, 'medium');
  assert.equal(find(audit(['pref=1; SameSite=Lax'], 'http://app.example.com/'), 'missing-secure'), undefined);
  assert.ok(find(r, 'missing-secure').fix.includes('Secure'));
});
test('missing HttpOnly only for session-like names; csrf excluded; custom patterns', () => {
  const r = audit(['PHPSESSID=1; Secure; SameSite=Lax', 'csrf_token=1; Secure; SameSite=Lax', 'theme=1; Secure; SameSite=Lax', 'acme_u=1; Secure; SameSite=Lax']);
  assert.ok(find(r, 'missing-httponly', 'PHPSESSID'));
  assert.equal(find(r, 'missing-httponly', 'csrf_token'), undefined);
  assert.equal(find(r, 'missing-httponly', 'theme'), undefined);
  assert.equal(find(r, 'missing-httponly', 'acme_u'), undefined);
  const r2 = audit(['acme_u=1; Secure; SameSite=Lax'], undefined, { sessionPatterns: ['^acme_'] });
  assert.ok(find(r2, 'missing-httponly', 'acme_u'));
});
test('SameSite: missing, None, None without Secure (error), invalid', () => {
  const r = audit(['a=1; Secure', 'b=1; Secure; SameSite=None', 'c=1; SameSite=None', 'd=1; Secure; SameSite=Loose']);
  assert.ok(find(r, 'samesite-missing', 'a'));
  assert.ok(find(r, 'samesite-none', 'b'));
  assert.equal(find(r, 'samesite-none-insecure', 'c').severity, 'high');
  assert.ok(find(r, 'samesite-invalid', 'd'));
});
test('__Host- and __Secure- prefix violations', () => {
  const r = audit(['__Host-a=1; Secure; Path=/; Domain=app.example.com; SameSite=Lax', '__Host-b=1; Path=/; SameSite=Lax', '__Host-c=1; Secure; SameSite=Lax', '__Secure-d=1; SameSite=Lax', '__secure-e=1; Secure; SameSite=Lax', '__Secure-ok=1; Secure; SameSite=Lax']);
  assert.match(find(r, 'host-prefix', '__Host-a').message, /Domain/);
  assert.match(find(r, 'host-prefix', '__Host-b').message, /Secure/);
  assert.match(find(r, 'host-prefix', '__Host-c').message, /Path/);
  assert.ok(find(r, 'secure-prefix', '__Secure-d'));
  assert.equal(find(r, 'host-prefix', '__secure-e').severity, 'medium');
  assert.deepEqual(rules(r, '__Secure-ok'), []);
  assert.match(find(audit(['__Secure-x=1; Secure; SameSite=Lax'], 'http://a.test/'), 'secure-prefix').message, /non-HTTPS/);
});
test('broad Domain / mismatched Domain / Path=/ on sensitive cookies', () => {
  const r = audit(['session=1; Secure; HttpOnly; SameSite=Lax; Domain=.example.com; Path=/', 'x=1; Secure; SameSite=Lax; Domain=evil.com', 'y=1; Secure; SameSite=Lax; Domain=com']);
  assert.equal(find(r, 'broad-domain', 'session').severity, 'medium');
  assert.match(find(r, 'broad-domain', 'session').message, /parent of app\.example\.com/);
  assert.ok(find(r, 'domain-mismatch', 'x'));
  assert.ok(find(r, 'broad-path', 'session'));
  assert.equal(find(audit(['y=1; Secure; SameSite=Lax; Domain=com'], 'https://com/'), 'broad-domain', 'y').severity, 'high');
});
test('excessive Expires / Max-Age with separate limits; deletions ignored', () => {
  const r = audit(['auth=1; Secure; HttpOnly; SameSite=Lax; Max-Age=7776000', 'pref=1; Secure; SameSite=Lax; Expires=Wed, 01 Jan 2031 00:00:00 GMT', 'ok=1; Secure; SameSite=Lax; Max-Age=86400', 'gone=; Max-Age=0', 'sid=; Expires=Thu, 01 Jan 1970 00:00:00 GMT']);
  assert.match(find(r, 'long-expiry', 'auth').message, /90 days/);
  assert.ok(find(r, 'long-expiry', 'pref'));
  assert.equal(find(r, 'long-expiry', 'ok'), undefined);
  assert.deepEqual(rules(r, 'gone'), []); assert.deepEqual(rules(r, 'sid'), []);
  assert.equal(find(audit(['auth=1; Secure; HttpOnly; SameSite=Lax; Max-Age=7776000'], undefined, { sessionMaxAgeDays: 120 }), 'long-expiry'), undefined);
});
test('cookies over http, large cookies', () => {
  const r = audit(['session=1; HttpOnly; SameSite=Lax', `blob=${'a'.repeat(5000)}; SameSite=Lax`, `mid=${'a'.repeat(3500)}; SameSite=Lax`], 'http://shop.test/');
  assert.equal(find(r, 'cookie-over-http', 'session').severity, 'high');
  assert.equal(find(r, 'large-cookie', 'blob').severity, 'medium');
  assert.equal(find(r, 'large-cookie', 'mid').severity, 'low');
});
test('sensitive data: JWT, alg none, emails (plain, url-encoded, base64)', () => {
  const h = Buffer.from('{"alg":"HS256"}').toString('base64url'); const p = Buffer.from('{"sub":"1","email":"bob@corp.io"}').toString('base64url');
  const r = audit([`token=${h}.${p}.sig; Secure; HttpOnly; SameSite=Lax`, 'em=carol%40x.org; Secure; SameSite=Lax', `b=${Buffer.from('user=dave@y.net').toString('base64')}; Secure; SameSite=Lax`,
    `n=${Buffer.from('{"alg":"none"}').toString('base64url')}.${Buffer.from('{"a":1}').toString('base64url')}.; Secure; SameSite=Lax`]);
  assert.equal(find(r, 'sensitive-jwt', 'token').severity, 'medium');
  assert.match(find(r, 'sensitive-jwt', 'token').message, /sub, email/);
  assert.ok(find(r, 'sensitive-email', 'token'));
  assert.ok(find(r, 'sensitive-email', 'em')); assert.ok(find(r, 'sensitive-email', 'b'));
  assert.equal(find(r, 'jwt-alg-none', 'n').severity, 'critical');
  assert.equal(find(r, 'sensitive-jwt', 'n').severity, 'high'); // not HttpOnly
});
test('duplicates in one response and across scopes', () => {
  const r = audit(['a=1; Secure; SameSite=Lax', 'a=2; Secure; SameSite=Lax', '---', 'sid=1; Secure; HttpOnly; SameSite=Lax; Path=/', '@ /admin', 'sid=2; Secure; HttpOnly; SameSite=Lax; Path=/admin']);
  assert.match(find(r, 'duplicate-cookie', 'a').message, /2 times in the same response/);
  assert.match(find(r, 'duplicate-cookie', 'sid').message, /different Domain\/Path/);
  assert.equal(r.findings.filter((f) => f.rule === 'duplicate-cookie').length, 2);
});
test('Partitioned misuse', () => {
  const r = audit(['p1=1; Partitioned; SameSite=None', 'p2=1; Secure; Partitioned; SameSite=Lax', 'p3=1; Secure; Partitioned; SameSite=None']);
  assert.ok(find(r, 'partitioned-insecure', 'p1'));
  assert.ok(find(r, 'partitioned-misuse', 'p2'));
  assert.equal(find(r, 'partitioned-misuse', 'p3'), undefined);
});
test('config: severity overrides, off, allowlist (object and string), suppressed list', () => {
  const lines = ['sid=1; SameSite=Lax', 'theme=1'];
  const r = audit(lines, undefined, { severity: { 'samesite-missing': 'off', 'missing-httponly': 'critical' }, allow: [{ rule: 'missing-secure', cookie: 's*', reason: 'legacy' }, 'theme'] });
  assert.equal(find(r, 'missing-httponly', 'sid').severity, 'critical');
  assert.equal(find(r, 'samesite-missing'), undefined);
  assert.equal(find(r, 'missing-secure', 'sid'), undefined);
  assert.deepEqual(rules(r, 'theme'), []);
  assert.ok(r.suppressed.some((s) => s.allowedBy === 'legacy'));
  assert.equal(r.findings[0].severity, 'critical'); // sorted
});
test('exceeds() honours fail-on', () => {
  const r = audit(['theme=1; Secure']); // low only
  assert.equal(exceeds(r, 'high'), false); assert.equal(exceeds(r, 'low'), true); assert.equal(exceeds(r, 'none'), false);
});
