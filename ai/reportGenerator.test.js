import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import {
  buildHtml,
  readNikto,
  readNuclei,
  readManualTests,
} from './reportGenerator.js';

test('readNuclei: parses JSONL findings', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-module-report-'));
  const path = join(dir, 'nuclei-report.jsonl');
  writeFileSync(path, JSON.stringify({
    'template-id': 'exposed-admin-panel',
    'matched-at': 'http://api:3001/admin',
    info: {
      name: 'Exposed Admin Panel',
      severity: 'high',
      tags: 'exposure,admin',
      classification: { 'cwe-id': 'CWE-200' },
    },
  }) + '\n');

  const findings = readNuclei(path);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].source, 'nuclei');
  assert.equal(findings[0].severity, 'high');
  assert.equal(findings[0].category, 'info_leak');
  assert.equal(findings[0].cweId, 'CWE-200');
});

test('readNikto: parses host vulnerabilities', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-module-report-'));
  const path = join(dir, 'nikto-report.json');
  writeFileSync(path, JSON.stringify({
    hosts: [{
      hostname: 'api',
      vulnerabilities: [{
        id: '999001',
        msg: 'Server header disclosure',
        url: 'http://api:3001/',
      }],
    }],
  }));

  const findings = readNikto(path);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].source, 'nikto');
  assert.equal(findings[0].category, 'misconfig');
});

test('buildHtml: includes manual test checklist', () => {
  const html = buildHtml(
    {
      executive_summary: { key_findings: [], immediate_actions: [] },
      triaged_findings: [],
    },
    { techStack: { language: 'nodejs', framework: 'nodejs-rest-api' } },
    {
      manualTests: [{
        id: 'TC-001',
        vulnerability_type: 'IDOR',
        target_endpoint: 'PUT /api/users/:id',
        severity: 'HIGH',
        steps: [{ step: 1, action: 'Use account A token and change account B id.' }],
        remediation_hint: 'Enforce object ownership checks.',
      }],
    }
  );

  assert.match(html, /Manual Testing Checklist/);
  assert.match(html, /PUT \/api\/users\/:id/);
});

test('readManualTests: reads manual_test_cases array', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-module-report-'));
  const path = join(dir, 'manual_tests.json');
  writeFileSync(path, JSON.stringify({
    manual_test_cases: [{ id: 'TC-001', vulnerability_type: 'IDOR' }],
  }));

  assert.equal(readManualTests(path).length, 1);
});
