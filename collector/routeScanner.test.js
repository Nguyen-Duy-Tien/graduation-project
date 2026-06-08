import { test } from 'node:test';
import assert from 'node:assert/strict';
import { collectRoutes } from './routeScanner.js';
import { resolveVulnerableRestApiTarget } from './testTarget.js';

test('collectRoutes: expands Express mounted routers into full API paths', async () => {
  const target = resolveVulnerableRestApiTarget();
  assert.ok(target, 'vulnerable-rest-api fixture not found');

  const routes = await collectRoutes(target, {
    language: 'nodejs',
    framework: 'nodejs-rest-api',
  });

  const keys = new Set(routes.routes.map(r => `${r.method} ${r.path}`));

  assert.ok(keys.has('PUT /api/users/:id'));
  assert.ok(keys.has('POST /api/users/otp'));
  assert.ok(keys.has('GET /api/system/key'));
  assert.ok(keys.has('GET /api/me'));
  assert.ok(!keys.has('USE /api/users'));

  const userUpdate = routes.routes.find(r => r.method === 'PUT' && r.path === '/api/users/:id');
  assert.deepEqual(userUpdate.classification.includes('idor_candidate'), true);
  assert.equal(userUpdate.mountedFrom, 'server/startup/routes.js');
  assert.deepEqual(userUpdate.security.middleware, ['auth', 'validateObjectId']);
  assert.equal(userUpdate.security.hasAuthMiddleware, true);
  assert.equal(userUpdate.security.hasRoleCheck, false);
  assert.equal(userUpdate.security.missingOwnershipSignal, true);
  assert.ok(userUpdate.classification.includes('missing_ownership_check'));

  const bookDelete = routes.routes.find(r => r.method === 'DELETE' && r.path === '/api/books/:id');
  assert.deepEqual(bookDelete.security.middleware, ['auth']);
  assert.equal(bookDelete.security.weakFunctionAuthzSignal, true);
  assert.ok(bookDelete.security.riskSignals.includes('state_changing_route_without_role_check'));
});
