import { test } from 'node:test';
import assert from 'node:assert/strict';
import { collectSchemas } from './schemaScanner.js';
import { resolveVulnerableRestApiTarget } from './testTarget.js';

test('collectSchemas: detects sensitive Mongoose fields for manual test generation', async () => {
  const target = resolveVulnerableRestApiTarget();
  assert.ok(target, 'vulnerable-rest-api fixture not found');

  const result = await collectSchemas(target);
  const user = result.models.find(model => model.name === 'User');

  assert.ok(user);
  assert.equal(user.file, 'server/models/user.js');
  assert.ok(user.fields.includes('role'));
  assert.ok(user.fields.includes('credit'));
  assert.ok(user.fields.includes('password'));
  assert.ok(user.sensitiveFields.some(item => item.field === 'role' && item.tags.includes('privilege')));
  assert.ok(user.massAssignmentTargets.includes('role'));
  assert.ok(user.massAssignmentTargets.includes('credit'));
  assert.ok(result.sensitiveFieldCount >= 3);
});
