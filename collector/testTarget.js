import { existsSync } from 'fs';
import { dirname, resolve } from 'path';
import { fileURLToPath } from 'url';

const here = dirname(fileURLToPath(import.meta.url));

export function resolveVulnerableRestApiTarget() {
  const candidates = [
    resolve(here, '../examples/vulnerable-rest-api'),
    resolve(here, '../../vulnerable-rest-api'),
    resolve(here, '../../Benchmark/vulnerable-rest-api'),
  ];

  return candidates.find(path => existsSync(path));
}
