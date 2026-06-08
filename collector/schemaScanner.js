// collector/schemaScanner.js
// Extract lightweight model/schema context so AI can generate more precise
// manual tests for mass assignment, privilege escalation, and ownership checks.

import { readFileSync } from 'fs';
import { basename, relative } from 'path';
import { glob } from 'glob';

const SKIP_DIRS = new Set([
  'node_modules', 'vendor', '.git', '__pycache__', 'dist',
  'build', '.venv', 'venv', 'target', '.next', 'coverage', 'tmp',
]);

const SOURCE_EXTENSIONS = ['.js', '.ts', '.mjs', '.cjs', '.py', '.java', '.php', '.go', '.rb', '.prisma'];

const SENSITIVE_FIELD_RULES = [
  { type: 'privilege', pattern: /^(?:role|roles|isAdmin|is_admin|admin|permission|permissions|scope|scopes)$/i },
  { type: 'credential', pattern: /(?:password|passwd|hash|salt|secret|apiKey|api_key|privateKey|private_key)/i },
  { type: 'token', pattern: /(?:token|otp|code|pin|reset|verify|verification)/i },
  { type: 'business_value', pattern: /(?:credit|balance|wallet|points|price|amount|quota|limit|discount)/i },
  { type: 'ownership', pattern: /^(?:owner|ownerId|owner_id|userId|user_id|accountId|account_id|tenantId|tenant_id|createdBy|created_by)$/i },
  { type: 'pii', pattern: /(?:email|phone|address|ssn|identity|nationalId|dob|birthday)/i },
];

function shouldSkip(filePath) {
  return filePath.replace(/\\/g, '/').split('/').some(p => SKIP_DIRS.has(p));
}

function unique(items) {
  return [...new Set(items.filter(Boolean))];
}

function classifyField(field) {
  const tags = [];
  for (const rule of SENSITIVE_FIELD_RULES) {
    if (rule.pattern.test(field)) tags.push(rule.type);
  }
  return tags;
}

function findMatchingBrace(text, openIndex) {
  let depth = 0;
  let quote = null;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;

  for (let i = openIndex; i < text.length; i++) {
    const ch = text[i];
    const next = text[i + 1];

    if (lineComment) {
      if (ch === '\n') lineComment = false;
      continue;
    }

    if (blockComment) {
      if (ch === '*' && next === '/') {
        blockComment = false;
        i++;
      }
      continue;
    }

    if (quote) {
      if (escaped) {
        escaped = false;
      } else if (ch === '\\') {
        escaped = true;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }

    if (ch === '/' && next === '/') {
      lineComment = true;
      i++;
      continue;
    }

    if (ch === '/' && next === '*') {
      blockComment = true;
      i++;
      continue;
    }

    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      continue;
    }

    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) return i;
    }
  }

  return -1;
}

function lineNumberAt(content, index) {
  return content.slice(0, index).split('\n').length;
}

function inferModelName(filePath, content, schemaStart) {
  const before = content.slice(0, Math.min(content.length, schemaStart + 2000));
  const mongooseModelRe = /mongoose\s*\.\s*model\s*\(\s*['"`]([A-Z][A-Za-z0-9_]*)['"`]/g;
  let match;
  let last = null;
  while ((match = mongooseModelRe.exec(before)) !== null) {
    last = match[1];
  }
  if (last) return last;

  const assignmentRe = /module\.exports\.([A-Z][A-Za-z0-9_]*)\s*=|exports\.([A-Z][A-Za-z0-9_]*)\s*=|const\s+([A-Z][A-Za-z0-9_]*)\s*=/g;
  while ((match = assignmentRe.exec(before)) !== null) {
    const name = match[1] || match[2] || match[3];
    if (name && !['Schema', 'ObjectId'].includes(name)) return name;
  }

  const base = basename(filePath).replace(/\.[^.]+$/, '');
  return base.charAt(0).toUpperCase() + base.slice(1);
}

function extractJsSchemaBlocks(content) {
  const blocks = [];
  const re = /(?:new\s+)?mongoose\s*\.\s*Schema\s*\(\s*\{/g;
  let match;

  while ((match = re.exec(content)) !== null) {
    const openBrace = content.lastIndexOf('{', re.lastIndex - 1);
    const closeBrace = findMatchingBrace(content, openBrace);
    if (openBrace === -1 || closeBrace === -1) continue;
    blocks.push({
      start: openBrace,
      end: closeBrace,
      body: content.slice(openBrace + 1, closeBrace),
    });
  }

  return blocks;
}

function extractObjectFields(body) {
  const fields = [];
  const fieldRe = /(?:^|[\n,{])\s*([A-Za-z_$][\w$]*)\s*:/g;
  let match;

  while ((match = fieldRe.exec(body)) !== null) {
    const field = match[1];
    if (['type', 'required', 'default', 'enum', 'ref', 'minlength', 'maxlength', 'select', 'unique', 'index'].includes(field)) {
      continue;
    }
    fields.push(field);
  }

  return unique(fields);
}

function extractPrismaModels(content) {
  const models = [];
  const modelRe = /model\s+([A-Z][A-Za-z0-9_]*)\s*\{/g;
  let match;

  while ((match = modelRe.exec(content)) !== null) {
    const openBrace = content.indexOf('{', match.index);
    const closeBrace = findMatchingBrace(content, openBrace);
    if (closeBrace === -1) continue;

    const body = content.slice(openBrace + 1, closeBrace);
    const fields = body
      .split(/\r?\n/)
      .map(line => line.trim().match(/^([A-Za-z_][\w]*)\s+/)?.[1])
      .filter(field => field && !field.startsWith('@@'));

    models.push({
      name: match[1],
      line: lineNumberAt(content, match.index),
      fields: unique(fields),
      schemaType: 'prisma',
    });
  }

  return models;
}

function extractClassModels(content) {
  const models = [];
  const classRe = /class\s+([A-Z][A-Za-z0-9_]*)[\s\S]{0,4000}?\{/g;
  let match;

  while ((match = classRe.exec(content)) !== null) {
    const openBrace = content.indexOf('{', match.index);
    const closeBrace = findMatchingBrace(content, openBrace);
    if (closeBrace === -1) continue;

    const body = content.slice(openBrace + 1, closeBrace);
    const fields = [
      ...body.matchAll(/\b(?:public|private|protected)?\s*(?:readonly\s+)?([A-Za-z_][\w]*)\s*[=:;]/g),
    ].map(m => m[1]).filter(f => !['constructor', 'return'].includes(f));

    if (fields.length) {
      models.push({
        name: match[1],
        line: lineNumberAt(content, match.index),
        fields: unique(fields),
        schemaType: 'class',
      });
    }
  }

  return models;
}

function enrichModel(model, file) {
  const sensitiveFields = model.fields
    .map(field => ({ field, tags: classifyField(field) }))
    .filter(item => item.tags.length > 0);

  const ownershipFields = sensitiveFields
    .filter(item => item.tags.includes('ownership'))
    .map(item => item.field);

  return {
    ...model,
    file,
    fields: model.fields.slice(0, 80),
    sensitiveFields,
    ownershipFields,
    massAssignmentTargets: sensitiveFields
      .filter(item => ['privilege', 'business_value', 'credential', 'token'].some(tag => item.tags.includes(tag)))
      .map(item => item.field),
  };
}

function scanFile(filePath, projectRoot) {
  let content;
  try {
    content = readFileSync(filePath, 'utf8');
  } catch {
    return [];
  }

  const relPath = relative(projectRoot, filePath).replace(/\\/g, '/');
  const models = [];

  if (filePath.endsWith('.prisma')) {
    models.push(...extractPrismaModels(content));
  }

  for (const block of extractJsSchemaBlocks(content)) {
    models.push({
      name: inferModelName(filePath, content, block.start),
      line: lineNumberAt(content, block.start),
      fields: extractObjectFields(block.body),
      schemaType: 'mongoose',
    });
  }

  if (models.length === 0) {
    models.push(...extractClassModels(content));
  }

  return models
    .filter(model => model.fields.length > 0)
    .map(model => enrichModel(model, relPath));
}

function buildFieldIndex(models) {
  const bySensitiveField = {};

  for (const model of models) {
    for (const item of model.sensitiveFields) {
      bySensitiveField[item.field] = bySensitiveField[item.field] ?? [];
      bySensitiveField[item.field].push({
        model: model.name,
        file: model.file,
        tags: item.tags,
      });
    }
  }

  return { bySensitiveField };
}

export async function collectSchemas(projectRoot) {
  const fileGlobs = SOURCE_EXTENSIONS.map(ext => `**/*${ext}`);
  const allFiles = (await Promise.all(
    fileGlobs.map(p => glob(p, { cwd: projectRoot, absolute: true, dot: false }))
  )).flat().filter(f => !shouldSkip(f));

  const models = [];
  for (const file of unique(allFiles)) {
    models.push(...scanFile(file, projectRoot));
  }

  const modelsWithSensitiveFields = models.filter(model => model.sensitiveFields.length > 0);

  return {
    totalModels: models.length,
    models,
    modelsWithSensitiveFields,
    sensitiveFieldCount: modelsWithSensitiveFields.reduce((sum, model) => sum + model.sensitiveFields.length, 0),
    fieldIndex: buildFieldIndex(modelsWithSensitiveFields),
    filesScanned: unique(allFiles).length,
  };
}
