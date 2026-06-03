import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'path';
import { collectRoutes } from './routeScanner.js';

test('collectRoutes: expands Express mounted routers into full API paths', async () => {
  const routes = await collectRoutes(resolve('examples/vulnerable-rest-api'), {
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
});
