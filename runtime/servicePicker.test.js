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
  assert.equal(result.serviceName, 'api');
  assert.equal(result.port, '3001');
  assert.equal(result.networkName, 'vulnerable-rest-api_default');
  assert.equal(result.composeFile, 'docker-compose.yml');
});

test('prefers api service over client service', () => {
  const ci = {
    hasDockerCompose: true,
    composeFile: 'docker-compose.yml',
    dockerCompose: {
      servicesDetail: [
        { name: 'client', image: null, build: './client', ports: ['3000:3000'], depends_on: ['api'] },
        { name: 'api',    image: null, build: './server', ports: ['3001:3001'], depends_on: ['db'] },
        { name: 'db',     image: 'mongo:6', build: null, ports: ['27017:27017'], depends_on: [] },
      ],
    },
  };
  const result = pickTargetService(ci, projectRoot);
  assert.equal(result.serviceName, 'api');
  assert.equal(result.port, '3001');
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
  assert.equal(result.port, '80');
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

test('parses compose env default syntax in port mappings', () => {
  const ci = {
    hasDockerCompose: true,
    dockerCompose: {
      servicesDetail: [
        { name: 'crapi-web', image: 'crapi/crapi-web:latest', ports: ['${LISTEN_IP:-127.0.0.1}:8888:80'] },
      ],
    },
  };

  const result = pickTargetService(ci, '/tmp/crapi');
  assert.equal(result.serviceName, 'crapi-web');
  assert.equal(result.port, '80');
});

test('prefers crAPI web target over chatbot and mail UI', () => {
  const ci = {
    hasDockerCompose: true,
    composeFile: 'deploy/docker/docker-compose.yml',
    dockerCompose: {
      servicesDetail: [
        { name: 'crapi-chatbot', image: 'crapi/crapi-chatbot:latest', ports: ['${LISTEN_IP:-127.0.0.1}:5500:5500'] },
        { name: 'crapi-web', image: 'crapi/crapi-web:latest', ports: ['${LISTEN_IP:-127.0.0.1}:8888:80'] },
        { name: 'mailhog', image: 'crapi/mailhog:latest', ports: ['${LISTEN_IP:-127.0.0.1}:8025:8025'] },
      ],
    },
  };

  const result = pickTargetService(ci, '/tmp/crapi');
  assert.equal(result.serviceName, 'crapi-web');
  assert.equal(result.port, '80');
});

test('uses declared compose service network for DAST scanners', () => {
  const ci = {
    hasDockerCompose: true,
    composeFile: 'compose.yaml',
    dockerCompose: {
      networksDetail: [{ name: 'sqlinet', actualName: null, external: false }],
      servicesDetail: [
        { name: 'db', image: 'mysql:5.7', ports: ['3306:3306'], networks: ['sqlinet'] },
        { name: 'web', image: null, build: './web', ports: ['5000:5000'], networks: ['sqlinet'], depends_on: ['db'] },
      ],
    },
  };

  const result = pickTargetService(ci, '/tmp/sqli');
  assert.equal(result.serviceName, 'web');
  assert.equal(result.port, '5000');
  assert.equal(result.networkName, 'sqli_sqlinet');
  assert.equal(result.composeFile, 'compose.yaml');
});

test('uses root project name for nested compose networks', () => {
  const ci = {
    hasDockerCompose: true,
    composeFile: 'deploy/docker/docker-compose.yml',
    composeDir: 'deploy/docker',
    dockerCompose: {
      networksDetail: [{ name: 'crapi-net', actualName: null, external: false }],
      servicesDetail: [
        { name: 'gateway', image: 'crapi/gateway', ports: ['8888:80'], networks: ['crapi-net'], depends_on: ['mongodb'] },
        { name: 'mongodb', image: 'mongo:5', ports: ['27017:27017'], networks: ['crapi-net'] },
      ],
    },
  };

  const result = pickTargetService(ci, '/tmp/crapi');
  assert.equal(result.serviceName, 'gateway');
  assert.equal(result.port, '80');
  assert.equal(result.networkName, 'crapi_crapi-net');
  assert.equal(result.composeFile, 'deploy/docker/docker-compose.yml');
  assert.equal(result.composeProjectName, 'crapi');
});

test('resolves nested compose build contexts from compose directory', () => {
  const ci = {
    hasDockerCompose: true,
    composeFile: 'deploy/docker/docker-compose.yml',
    composeDir: 'deploy/docker',
    dockerCompose: {
      servicesDetail: [
        { name: 'frontend', image: null, build: '../../client', ports: ['3000:3000'], depends_on: ['api'] },
        { name: 'api', image: null, build: '../../server', ports: ['3001:3001'], depends_on: ['db'] },
      ],
    },
  };

  const result = pickTargetService(ci, '/tmp/vulnerable-rest-api');
  assert.equal(result.serviceName, 'api');
  assert.equal(result.composeProjectName, 'vulnerable-rest-api');
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
