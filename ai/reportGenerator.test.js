import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import {
  buildHtml,
  readNikto,
  readNuclei,
  readZap,
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

test('readZap: keeps alert instances as separate findings', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-module-report-'));
  const path = join(dir, 'zap-report.json');
  writeFileSync(path, JSON.stringify({
    site: [{
      '@name': 'http://web:5000',
      alerts: [{
        pluginid: '40018',
        alert: 'SQL Injection',
        riskdesc: 'High',
        cweid: '89',
        instances: [
          { method: 'GET', uri: 'http://web:5000/search', param: 'q', evidence: 'SQL syntax error' },
          { method: 'POST', uri: 'http://web:5000/login', param: 'username', evidence: 'mysql_fetch' },
        ],
      }],
    }],
  }));

  const findings = readZap(path);
  assert.equal(findings.length, 2);
  assert.match(findings[0].location, /GET http:\/\/web:5000\/search param=q/);
  assert.equal(findings[1].param, 'username');
  assert.equal(findings[1].evidence, 'mysql_fetch');
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

test('buildHtml: shows exact finding location and evidence', () => {
  const html = buildHtml(
    {
      executive_summary: { key_findings: [], immediate_actions: [] },
      triaged_findings: [{
        id: 'F-001',
        triage_status: 'confirmed_vulnerability',
        triage_reason: 'Evidence indicates injectable SQL behavior.',
        risk_score: 90,
        remediation: { summary: 'Use parameterized queries.' },
        original_finding: {
          source: 'zap',
          ruleId: '40018',
          category: 'sqli',
          severity: 'high',
          location: 'GET http://web:5000/search param=q',
          param: 'q',
          evidence: 'SQL syntax error',
          message: 'SQL Injection',
          cweId: 'CWE-89',
        },
      }],
    },
    { techStack: { language: 'python', framework: 'python-flask' } },
  );

  assert.match(html, /class="findings-list"/);
  assert.match(html, /Where/);
  assert.match(html, /GET http:\/\/web:5000\/search param=q/);
  assert.match(html, /Evidence/);
  assert.match(html, /SQL syntax error/);
});

test('readManualTests: reads manual_test_cases array', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-module-report-'));
  const path = join(dir, 'manual_tests.json');
  writeFileSync(path, JSON.stringify({
    manual_test_cases: [{ id: 'TC-001', vulnerability_type: 'IDOR' }],
  }));

  assert.equal(readManualTests(path).length, 1);
});
