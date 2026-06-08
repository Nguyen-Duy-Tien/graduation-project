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
        why_generated: 'Endpoint has object id and lacks ownership evidence.',
        evidence: {
          route: 'server/routes/users.js:31',
          classification: ['idor_candidate', 'missing_ownership_check'],
          middleware: ['auth', 'validateObjectId'],
          risk_signals: ['object_identifier_route_without_req_user_ownership_check'],
          schema_fields: ['role', 'credit'],
        },
        steps: [{ step: 1, action: 'Use account A token and change account B id.' }],
        remediation_hint: 'Enforce object ownership checks.',
      }],
    }
  );

  assert.match(html, /Manual Testing Checklist/);
  assert.match(html, /PUT \/api\/users\/:id/);
  assert.match(html, /Why Generated/);
  assert.match(html, /Endpoint has object id and lacks ownership evidence/);
  assert.match(html, /object_identifier_route_without_req_user_ownership_check/);
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
  assert.match(html, /Vulnerability Location/);
  assert.match(html, /GET http:\/\/web:5000\/search param=q/);
  assert.match(html, /Evidence/);
  assert.match(html, /SQL syntax error/);
  assert.match(html, /class="finding-analysis"/);
  assert.match(html, /class="analysis-box triage-reason"/);
  assert.match(html, /gap: 2\.25rem/);
});

test('buildHtml: shows tool run counts and AI filtered findings', () => {
  const html = buildHtml(
    {
      executive_summary: { key_findings: [], immediate_actions: [] },
      tool_runs: [
        { key: 'semgrep', label: 'Semgrep', file: 'semgrep-report.json', exists: true, findingCount: 4 },
        { key: 'zap', label: 'ZAP', file: 'zap-report.json', exists: false, findingCount: 0 },
      ],
      triaged_findings: [{
        id: 'F-010',
        triage_status: 'false_positive',
        triage_reason: 'Dependency not reachable in runtime path.',
        risk_score: 5,
        remediation: { summary: 'No action required.' },
        original_finding: {
          source: 'semgrep',
          ruleId: 'test.rule',
          category: 'general',
          severity: 'low',
          file: 'app.js',
          line: 10,
          message: 'Scanner-only finding',
        },
      }],
    },
    { techStack: { language: 'nodejs', framework: 'nodejs-rest-api' } },
  );

  assert.match(html, /Tool Run Summary/);
  assert.match(html, /Semgrep/);
  assert.match(html, /4 findings/);
  assert.match(html, /missing zap-report\.json/);
  assert.match(html, /AI Filtered Findings/);
  assert.match(html, /Scanner-only finding/);
});

test('buildHtml: lists only tools passed in metadata', () => {
  const html = buildHtml(
    {
      executive_summary: { key_findings: [], immediate_actions: [] },
      triaged_findings: [],
    },
    { techStack: { language: 'python', framework: 'python-flask' } },
    { tools: ['Semgrep', 'Bandit', 'Trivy'] },
  );

  assert.match(html, /Tools: Semgrep · Bandit · Trivy · AI Triage/);
  assert.doesNotMatch(html, /Tools: .*ZAP/);
});

test('buildHtml: uses normalized severity counts from summary', () => {
  const html = buildHtml(
    {
      executive_summary: {
        critical_count: 6,
        high_count: 2,
        medium_count: 1,
        key_findings: [],
        immediate_actions: [],
      },
      triaged_findings: [],
    },
    { techStack: { language: 'python', framework: 'python-flask' } },
    { tools: ['Semgrep'] },
  );

  assert.match(html, />6<\/div>\s*<div class="stat-label">Critical/);
});

test('readManualTests: reads manual_test_cases array', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ai-module-report-'));
  const path = join(dir, 'manual_tests.json');
  writeFileSync(path, JSON.stringify({
    manual_test_cases: [{ id: 'TC-001', vulnerability_type: 'IDOR' }],
  }));

  assert.equal(readManualTests(path).length, 1);
});
