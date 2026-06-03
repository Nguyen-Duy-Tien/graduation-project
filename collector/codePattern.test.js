import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'path';
import { collectCodePatterns } from './codePattern.js';

test('collectCodePatterns: detects OWASP API benchmark patterns', async () => {
  const result = await collectCodePatterns(resolve('examples/vulnerable-rest-api'));
  const ids = new Set(result.topFindings.map(f => f.patternId));
  const allByCategory = result.byCategory;

  assert.ok(allByCategory.mass_assign?.findings.some(f => f.patternId === 'mass-3'));
  assert.ok(allByCategory.ssrf?.findings.some(f => f.patternId === 'ssrf-3'));
  assert.ok(allByCategory.nosqli?.findings.some(f => f.patternId === 'nosqli-1' || f.patternId === 'nosqli-2'));
  assert.ok(allByCategory.info_leak?.findings.some(f => f.patternId === 'info-2'));
  assert.ok(allByCategory.redos?.findings.some(f => f.patternId === 'redos-1'));
  assert.ok(allByCategory.auth_bypass?.findings.some(f => f.patternId === 'auth-3'));

  assert.ok(ids.has('nosqli-1') || ids.has('nosqli-2'));
  assert.ok(result.bySeverity.critical >= 1);
  assert.ok(result.totalFindings > 2);
});
