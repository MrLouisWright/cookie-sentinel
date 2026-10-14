import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { classifyCookie, lookupOpenCookieDatabase, cookieParty, purposeFromCategory } from '../src/classify.js';
import { parseSetCookie } from '../src/parse.js';

describe('Open Cookie Database classification', () => {
  it('looks up known cookies', () => {
    const hit = lookupOpenCookieDatabase('_ga');
    assert.ok(hit);
    assert.equal(hit.category, 'Analytics');
  });

  it('classifies first-party vs third-party', () => {
    assert.equal(cookieParty('https://app.example.com/', undefined, null), 'first-party');
    assert.equal(cookieParty('https://app.example.com/', '.evil.com', null), 'third-party');
  });

  it('maps categories to tracking/essential purpose', () => {
    assert.equal(purposeFromCategory('Analytics'), 'tracking');
    assert.equal(purposeFromCategory('Functional'), 'essential');
  });

  it('enriches parsed cookies', () => {
    const cookie = parseSetCookie('_ga=1; Path=/; Secure');
    const cl = classifyCookie(cookie, 'https://www.example.com/');
    assert.equal(cl.purpose, 'tracking');
    assert.equal(cl.party, 'first-party');
  });
});
