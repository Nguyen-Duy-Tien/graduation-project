import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { collectContainerInfo } from './apiSurface.js';

test('collectContainerInfo finds nested docker-compose files', async () => {
  const root = mkdtempSync(join(tmpdir(), 'nested-compose-'));
  mkdirSync(join(root, 'deploy', 'docker'), { recursive: true });
  writeFileSync(join(root, 'deploy', 'docker', 'docker-compose.yml'), `
services:
  gateway:
    image: crapi/gateway
    ports:
      - "8888:80"
    networks:
      - crapi-net
  mongodb:
    image: mongo:5
    ports:
      - "27017:27017"
networks:
  crapi-net:
    driver: bridge
`, 'utf8');

  const info = await collectContainerInfo(root);

  assert.equal(info.hasDockerCompose, true);
  assert.equal(info.composeFile, 'deploy/docker/docker-compose.yml');
  assert.equal(info.composeDir, 'deploy/docker');
  assert.deepEqual(info.dockerCompose.services, ['gateway', 'mongodb']);
  assert.equal(info.dockerCompose.servicesDetail[0].name, 'gateway');
});
