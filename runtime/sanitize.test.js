// runtime/sanitize.test.js
// Run: node --test runtime/sanitize.test.js

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  assertRuleset, assertZapMode, assertServiceName, assertPort, assertSeverityList,
  sanitizeRulesets, sanitizeNucleiTags, sanitizeFocusPaths, sanitizeImageRefs,
  shellQuote,
} from './sanitize.js';

test('assertRuleset: accepts valid', () => {
  assert.equal(assertRuleset('p/nodejs'), 'p/nodejs');
  assert.equal(assertRuleset('p/owasp-top-ten'), 'p/owasp-top-ten');
});

test('assertRuleset: rejects injection', () => {
  assert.throws(() => assertRuleset('p/x; rm -rf /'));
  assert.throws(() => assertRuleset('r/foo'));
  assert.throws(() => assertRuleset('p/'));
});

test('assertZapMode: enum only', () => {
  assert.equal(assertZapMode('baseline'), 'baseline');
  assert.throws(() => assertZapMode('baseline;curl evil'));
  assert.throws(() => assertZapMode('full'));
});

test('assertServiceName: docker compatible', () => {
  assert.equal(assertServiceName('api'), 'api');
  assert.equal(assertServiceName('web_app-1'), 'web_app-1');
  assert.throws(() => assertServiceName('api && rm'));
  assert.throws(() => assertServiceName(''));
});

test('assertPort: numeric range 1-65535', () => {
  assert.equal(assertPort('3001'), '3001');
  assert.equal(assertPort('80'), '80');
  assert.throws(() => assertPort('0'));
  assert.throws(() => assertPort('99999'));
  assert.throws(() => assertPort('3001;'));
});

test('assertSeverityList: comma-separated enum', () => {
  assert.equal(assertSeverityList('medium,high,critical'), 'medium,high,critical');
  assert.equal(assertSeverityList('low'), 'low');
  assert.throws(() => assertSeverityList('medium,foo'));
});

test('sanitizeRulesets: drops bad entries, keeps good', () => {
  const result = sanitizeRulesets(['p/nodejs', 'p/x;rm', 'p/jwt', 42, null]);
  assert.deepEqual(result, ['p/nodejs', 'p/jwt']);
});

test('sanitizeNucleiTags: drops bad', () => {
  const result = sanitizeNucleiTags(['cve', 'cve;curl', 'file-upload', 'jwt_auth']);
  assert.deepEqual(result, ['cve', 'file-upload', 'jwt_auth']);
});

test('sanitizeFocusPaths: drops path traversal', () => {
  const result = sanitizeFocusPaths(['/api/books', '/api;curl', '..\\..', '/v1/users/me']);
  assert.deepEqual(result, ['/api/books', '/v1/users/me']);
});

test('sanitizeImageRefs: accepts image refs and drops shell injection', () => {
  const result = sanitizeImageRefs([
    'bkimminich/juice-shop:latest',
    'registry.local:5000/team/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'alpine; curl evil',
  ]);
  assert.deepEqual(result, [
    'bkimminich/juice-shop:latest',
    'registry.local:5000/team/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  ]);
});

test('sanitizeRulesets: empty array on garbage input', () => {
  assert.deepEqual(sanitizeRulesets(null), []);
  assert.deepEqual(sanitizeRulesets('not-array'), []);
  assert.deepEqual(sanitizeRulesets([]), []);
});

test('shellQuote: escapes single quotes', () => {
  assert.equal(shellQuote('foo'), `'foo'`);
  assert.equal(shellQuote(`it's`), `'it'\\''s'`);
  assert.equal(shellQuote('E:\\đồ án tốt nghiệp\\'), `'E:\\đồ án tốt nghiệp\\'`);
});
