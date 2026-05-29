// runtime/servicePicker.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pickTargetService } from './servicePicker.js';

const projectRoot = '/tmp/vulnerable-rest-api';

test('returns null when no compose', () => {
  assert.equal(pickTargetService({ hasDockerCompose: false }, projectRoot), null);
});

test('picks api service over mongo', () => {
  const ci = {
    hasDockerCompose: true,
    composeFile: 'docker-compose.yml',
    dockerCompose: {
      servicesDetail: [
        { name: 'db',  image: 'mongo:5',     ports: ['27017:27017'] },
        { name: 'api', image: 'node:18',     ports: ['3001:3001']   },
      ],
    },
  };
  const result = pickTargetService(ci, projectRoot);
  assert.deepEqual(result, {
    serviceName: 'api',
    port: '3001',
    networkName: 'vulnerable-rest-api_default',
    composeFile: 'docker-compose.yml',
  });
});

test('skips service without ports', () => {
  const ci = {
    hasDockerCompose: true,
    dockerCompose: {
      servicesDetail: [
        { name: 'worker', image: 'node:18', ports: [] },
        { name: 'web',    image: 'node:18', ports: ['8080:80'] },
      ],
    },
  };
  const result = pickTargetService(ci, projectRoot);
  assert.equal(result.serviceName, 'web');
  assert.equal(result.port, '8080');
});

test('parses ip:host:container format', () => {
  const ci = {
    hasDockerCompose: true,
    dockerCompose: {
      servicesDetail: [
        { name: 'api', image: 'custom:1', ports: ['127.0.0.1:5000:5000'] },
      ],
    },
  };
  assert.equal(pickTargetService(ci, projectRoot).port, '5000');
});

test('skips port range', () => {
  const ci = {
    hasDockerCompose: true,
    dockerCompose: {
      servicesDetail: [
        { name: 'multi', image: 'x:1', ports: ['3001-3010:3001-3010'] },
      ],
    },
  };
  assert.equal(pickTargetService(ci, projectRoot), null);
});

test('returns null when only DB services', () => {
  const ci = {
    hasDockerCompose: true,
    dockerCompose: {
      servicesDetail: [
        { name: 'db',    image: 'postgres:14', ports: ['5432:5432'] },
        { name: 'cache', image: 'redis:7',    ports: ['6379:6379'] },
      ],
    },
  };
  assert.equal(pickTargetService(ci, projectRoot), null);
});

test('strips registry prefix when matching DB pattern', () => {
  const ci = {
    hasDockerCompose: true,
    dockerCompose: {
      servicesDetail: [
        { name: 'db',  image: 'docker.io/library/mongo:5', ports: ['27017:27017'] },
        { name: 'app', image: 'gcr.io/foo/myapp',           ports: ['8000:8000']   },
      ],
    },
  };
  assert.equal(pickTargetService(ci, projectRoot).serviceName, 'app');
});
