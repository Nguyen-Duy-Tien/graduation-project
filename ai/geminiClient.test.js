import test from 'node:test';
import assert from 'node:assert/strict';

import { parseJson } from './geminiClient.js';

test('parseJson parses a plain JSON object', () => {
  assert.deepEqual(parseJson('{"ok":true,"count":2}'), {
    ok: true,
    count: 2,
  });
});

test('parseJson parses fenced JSON', () => {
  assert.deepEqual(parseJson('```json\n{"manual_test_cases":[]}\n```'), {
    manual_test_cases: [],
  });
});

test('parseJson ignores prose after the first complete JSON object', () => {
  const parsed = parseJson('{"manual_test_cases":[{"id":"TC-001"}]}\nHere is why this matters.');
  assert.deepEqual(parsed, {
    manual_test_cases: [{ id: 'TC-001' }],
  });
});

test('parseJson ignores a duplicate JSON object after the first complete JSON object', () => {
  const parsed = parseJson('{"manual_test_cases":[{"id":"TC-001"}]}\n{"manual_test_cases":[{"id":"TC-002"}]}');
  assert.deepEqual(parsed, {
    manual_test_cases: [{ id: 'TC-001' }],
  });
});

test('parseJson keeps braces and brackets inside strings', () => {
  const parsed = parseJson('{"text":"curl -d {\\"role\\":\\"admin\\"} /api/users","items":["a]b","c}d"]} trailing');
  assert.deepEqual(parsed, {
    text: 'curl -d {"role":"admin"} /api/users',
    items: ['a]b', 'c}d'],
  });
});

test('parseJson parses a top-level array and ignores trailing text', () => {
  assert.deepEqual(parseJson('[{"id":1},{"id":2}]\nDone'), [
    { id: 1 },
    { id: 2 },
  ]);
});

test('parseJson throws on text without JSON', () => {
  assert.throws(() => parseJson('not json'), /parseJson failed:/);
});
