import { test } from 'node:test';
import assert from 'node:assert/strict';
import { collectTechStack } from './techStack.js';
import { resolveVulnerableRestApiTarget } from './testTarget.js';

test('collectTechStack: detects backend manifest from compose service subfolder', async () => {
  const target = resolveVulnerableRestApiTarget();
  assert.ok(target, 'vulnerable-rest-api fixture not found');

  const stack = await collectTechStack(target);

  assert.equal(stack.language, 'nodejs');
  assert.equal(stack.framework, 'nodejs-rest-api');
  assert.equal(stack.profileKey, 'nodejs-rest-api');
  assert.equal(stack.serviceName, 'api');
  assert.equal(stack.relativeRoot, 'server');
  assert.equal(stack.depFilePath, 'server/package.json');
  assert.equal(stack.features.jwt, true);
  assert.equal(stack.features.orm, true);
  assert.ok(stack.serviceCandidates.some(c => c.relativeRoot === 'client'));
  assert.ok(stack.serviceCandidates.some(c => c.relativeRoot === 'server'));
});
