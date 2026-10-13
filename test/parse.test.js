import test from 'node:test';
import assert from 'node:assert/strict';
import { parseSetCookie, splitCookiesString, lifetimeSeconds } from '../src/index.js';

test('parses attributes case-insensitively', () => {
  const c = parseSetCookie('Set-Cookie: __Host-id="v1"; SECURE; httponly; Path=/; SameSite=Strict; Max-Age=60; Partitioned; Foo');
  assert.equal(c.name, '__Host-id'); assert.equal(c.value, 'v1');
  assert.equal(c.attrs.secure, true); assert.equal(c.attrs.httpOnly, true); assert.equal(c.attrs.partitioned, true);
  assert.equal(c.attrs.path, '/'); assert.equal(c.attrs.sameSite, 'Strict'); assert.equal(c.attrs.maxAge, 60);
  assert.deepEqual(c.attrs.unknown, ['foo']);
});
test('rejects nameless / empty', () => { assert.equal(parseSetCookie('novalue'), null); assert.equal(parseSetCookie(''), null); assert.equal(parseSetCookie('=x'), null); });
test('lifetime: Max-Age wins over Expires; session cookie is null', () => {
  assert.equal(lifetimeSeconds(parseSetCookie('a=1; Expires=Wed, 21 Oct 2099 07:28:00 GMT; Max-Age=5')), 5);
  assert.equal(lifetimeSeconds(parseSetCookie('a=1')), null);
  assert.ok(lifetimeSeconds(parseSetCookie('a=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT')) < 0);
});
test('splits folded headers without breaking Expires dates', () => {
  assert.deepEqual(splitCookiesString('a=1; Expires=Wed, 21 Oct 2099 07:28:00 GMT, b=2; Path=/'), ['a=1; Expires=Wed, 21 Oct 2099 07:28:00 GMT', 'b=2; Path=/']);
  assert.deepEqual(splitCookiesString(['x=1', 'y=2, z=3']), ['x=1', 'y=2', 'z=3']);
});
