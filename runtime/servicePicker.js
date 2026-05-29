// runtime/servicePicker.js
// Heuristic chọn target service từ docker-compose để DAST attack vào.
//
// Quy tắc:
//   1. Loại trừ image database/cache/queue (mongo, postgres, mysql, redis, elastic...)
//   2. Loại trừ service không có port mapping (không thể attack từ ngoài)
//   3. Pick service đầu tiên còn lại theo thứ tự khai báo trong YAML
//   4. Nếu không pick được hoặc không có compose → return null → DAST skip
//
// Output:
//   { serviceName, port, networkName, composeFile } | null

import { basename } from 'path';
import {
  assertServiceName, assertNetworkName, assertPort,
} from './sanitize.js';

// Image database/cache/queue cần loại trừ — match theo prefix trước dấu ":" hoặc "/"
const DB_IMAGE_PATTERNS = [
  /^mongo(:|$|\/)/i,
  /^postgres(:|$|\/)/i,
  /^mysql(:|$|\/)/i,
  /^mariadb(:|$|\/)/i,
  /^redis(:|$|\/)/i,
  /^valkey(:|$|\/)/i,
  /^elastic(search)?(:|$|\/)/i,
  /^opensearch(:|$|\/)/i,
  /^rabbitmq(:|$|\/)/i,
  /^kafka(:|$|\/)/i,
  /^nats(:|$|\/)/i,
  /^minio(:|$|\/)/i,
  /^memcached(:|$|\/)/i,
  /^cassandra(:|$|\/)/i,
  /^clickhouse(:|$|\/)/i,
  /^influxdb(:|$|\/)/i,
  /^neo4j(:|$|\/)/i,
];

function isDbImage(image) {
  if (!image || typeof image !== 'string') return false;
  // Strip registry prefix nếu có (vd. "docker.io/library/mongo:5" → "mongo:5")
  const stripped = image.replace(/^.+\//, '');
  return DB_IMAGE_PATTERNS.some(re => re.test(stripped));
}

// Parse 1 entry trong ports[] của compose → host port (string)
//   "3001"               → "3001"
//   "3001:3001"          → "3001"
//   "127.0.0.1:3001:3001" → "3001"
//   "3001-3010:3001-3010" → null (range, bỏ)
function parseHostPort(portEntry) {
  if (typeof portEntry !== 'string') return null;
  const parts = portEntry.split(':');

  let candidate;
  if (parts.length === 1) {
    candidate = parts[0];                  // "3001"
  } else if (parts.length === 2) {
    candidate = parts[0];                  // "3001:3001"
  } else if (parts.length === 3) {
    candidate = parts[1];                  // "ip:host:container"
  } else {
    return null;
  }

  // Loại bỏ range "3001-3010"
  if (candidate.includes('-')) return null;
  // Loại bỏ "3001/tcp" suffix
  candidate = candidate.split('/')[0];

  if (!/^\d+$/.test(candidate)) return null;
  return candidate;
}

// Convention docker-compose: network mặc định = <basename>_default
// basename được lowercase và lọc ký tự không hợp lệ
function deriveNetworkName(projectRoot) {
  const base = basename(projectRoot)
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, '');
  if (!base) return 'default_default';
  return `${base}_default`;
}

/**
 * @param {object} containerInfo  — kết quả từ collectContainerInfo()
 * @param {string} projectRoot    — đường dẫn target project (để derive network)
 * @returns {object|null}
 */
export function pickTargetService(containerInfo, projectRoot) {
  if (!containerInfo?.hasDockerCompose) {
    return null;
  }

  const detail = containerInfo.dockerCompose?.servicesDetail ?? [];
  if (detail.length === 0) return null;

  // Lọc ứng viên: không phải DB và có port mapping
  const candidates = detail.filter(svc => !isDbImage(svc.image) && svc.ports.length > 0);
  if (candidates.length === 0) return null;

  // Pick đầu tiên hợp lệ sau sanitize
  for (const svc of candidates) {
    try {
      const serviceName = assertServiceName(svc.name);

      // Tìm host port hợp lệ đầu tiên
      let port = null;
      for (const p of svc.ports) {
        const hp = parseHostPort(p);
        if (hp) { port = hp; break; }
      }
      if (!port) continue;
      port = assertPort(port);

      const networkName = assertNetworkName(deriveNetworkName(projectRoot));
      const composeFile = containerInfo.composeFile ?? 'docker-compose.yml';

      return { serviceName, port, networkName, composeFile };
    } catch (err) {
      console.warn(`[servicePicker] skip ${svc.name}: ${err.message}`);
    }
  }

  return null;
}
