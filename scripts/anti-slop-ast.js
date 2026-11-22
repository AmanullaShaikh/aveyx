#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import _traverse from '@babel/traverse';
import { parseBabelAst } from './ast-parser.js';

const traverse = _traverse.default || _traverse;
const __filename = fileURLToPath(import.meta.url);

const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m'
};

const IGNORED_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', '.agents', '.worktrees', 'coverage']);

function isNullishOrBoolLiteral(node) {
  if (!node) return true;
  if (node.type === 'NullLiteral' || node.type === 'BooleanLiteral') return true;
  if (node.type === 'Identifier' && node.name === 'undefined') return true;
  if (node.type === 'UnaryExpression' && node.operator === 'void') return true;
  if (node.type === 'ObjectExpression' && node.properties.length === 0) return true;
  if (node.type === 'ArrayExpression' && node.elements.length === 0) return true;
  return false;
}

function getParamNames(params = []) {
  const names = [];
  for (const p of params) {
    if (p.type === 'Identifier') names.push(p.name);
    else return null;
  }
  return names;
}

/**
 * AST-based Anti-Slop Ruleset:
 * 1. Empty catch {} blocks (silent error swallowing)
 * 2. Silent catch { return null/undefined/false; } error masking
 * 3. Silent Promise .catch(() => {}) / .catch(() => null)
 * 4. Redundant 1:1 pass-through wrapper functions
 * 5. Empty exported stub functions / route handlers
 */
export function auditAntiSlopAst(code, filePath = 'unknown.ts') {
  const issues = [];
  if (!code || !code.trim()) return issues;

  let ast;
  try {
    ast = parseBabelAst(code);
  } catch {
    return issues;
  }

  const lines = code.split('\n');
  const getLineText = (line) => (lines[(line || 1) - 1] || '').trim().slice(0, 80);
  const hasIgnoreComment = (node) => {
    const start = Math.max(0, (node.loc?.start?.line || 1) - 1);
    const end = Math.min(lines.length, (node.loc?.end?.line || start + 1));
    const slice = lines.slice(start, end).join('\n');
    return /aveyx-ignore|intentional|ignore error|safe fallback|best[- ]effort/i.test(slice);
  };

  try {
    traverse(ast, {
      IfStatement(p) {
        if (hasIgnoreComment(p.node)) return;
        if (p.node.test?.type === 'BooleanLiteral' && p.node.test.value === false) {
          const line = p.node.loc?.start?.line || 1;
          issues.push({
            file: filePath,
            line,
            severity: 'MEDIUM',
            category: 'AI_SLOP_AST',
            type: 'DEAD_CODE_BRANCH',
            message: 'Unreachable dead branch "if (false)" left in production code.',
            snippet: getLineText(line)
          });
        }
      },

      CatchClause(p) {
        if (hasIgnoreComment(p.node)) return;
        const body = p.node.body?.body || [];
        const line = p.node.loc?.start?.line || 1;

        if (body.length === 0) {
          issues.push({
            file: filePath,
            line,
            severity: 'HIGH',
            category: 'AI_SLOP_AST',
            type: 'EMPTY_CATCH_BLOCK',
            message: 'Empty catch {} block silently swallows exceptions. Log, handle, or rethrow the error.',
            snippet: getLineText(line)
          });
          return;
        }

        if (body.length === 1 && body[0].type === 'ReturnStatement' && isNullishOrBoolLiteral(body[0].argument)) {
          issues.push({
            file: filePath,
            line,
            severity: 'MEDIUM',
            category: 'AI_SLOP_AST',
            type: 'SILENT_ERROR_MASKING',
            message: 'Catch block masks failure by silently returning null/undefined/boolean without logging or rethrowing.',
            snippet: getLineText(line)
          });
        }
      },

      CallExpression(p) {
        const callee = p.node.callee;
        if (callee?.type === 'MemberExpression' && callee.property?.name === 'catch' && p.node.arguments.length >= 1) {
          const handler = p.node.arguments[0];
          const line = p.node.loc?.start?.line || 1;
          if (hasIgnoreComment(p.node)) return;
          if (handler?.type === 'ArrowFunctionExpression' || handler?.type === 'FunctionExpression') {
            const isEmptyBlock = handler.body?.type === 'BlockStatement' && handler.body.body.length === 0;
            const isNullishBlock =
              handler.body?.type === 'BlockStatement' &&
              handler.body.body.length === 1 &&
              handler.body.body[0].type === 'ReturnStatement' &&
              isNullishOrBoolLiteral(handler.body.body[0].argument);
            const isNullishConcise = handler.body?.type !== 'BlockStatement' && isNullishOrBoolLiteral(handler.body);
            if (isEmptyBlock || isNullishBlock || isNullishConcise) {
              issues.push({
                file: filePath,
                line,
                severity: 'HIGH',
                category: 'AI_SLOP_AST',
                type: 'SILENT_PROMISE_SWALLOW',
                message: 'Promise .catch() silently swallows rejection without handling or logging.',
                snippet: getLineText(line)
              });
            }
          }
        }
      },

      VariableDeclarator(p) {
        if (hasIgnoreComment(p.node)) return;
        const isExported = p.parentPath?.parentPath?.isExportNamedDeclaration?.();
        const init = p.node.init;
        if (
          isExported &&
          p.node.id?.type === 'Identifier' &&
          init &&
          (init.type === 'ArrowFunctionExpression' || init.type === 'FunctionExpression') &&
          init.body?.type === 'BlockStatement' &&
          init.body.body.length === 0
        ) {
          const line = p.node.loc?.start?.line || 1;
          issues.push({
            file: filePath,
            line,
            severity: 'HIGH',
            category: 'AI_SLOP_AST',
            type: 'EMPTY_STUB_FUNCTION',
            message: `Exported function "${p.node.id.name}" has an empty body (unimplemented stub).`,
            snippet: getLineText(line)
          });
        }
      },

      FunctionDeclaration(p) {
        if (hasIgnoreComment(p.node)) return;
        const name = p.node.id?.name;
        const body = p.node.body?.body || [];
        const line = p.node.loc?.start?.line || 1;
        const isExported = p.parentPath?.isExportNamedDeclaration() || p.parentPath?.isExportDefaultDeclaration();

        if (isExported && body.length === 0) {
          issues.push({
            file: filePath,
            line,
            severity: 'HIGH',
            category: 'AI_SLOP_AST',
            type: 'EMPTY_STUB_FUNCTION',
            message: `Exported function "${name || 'default'}" has an empty body (unimplemented stub).`,
            snippet: getLineText(line)
          });
          return;
        }

        // Redundant 1:1 wrapper: function foo(a, b) { return bar(a, b); }
        if (!isExported && body.length === 1 && body[0].type === 'ReturnStatement' && body[0].argument?.type === 'CallExpression') {
          const call = body[0].argument;
          const paramNames = getParamNames(p.node.params);
          if (
            paramNames &&
            paramNames.length > 0 &&
            call.callee?.type === 'Identifier' &&
            call.callee.name !== name &&
            call.arguments.length === paramNames.length &&
            call.arguments.every((arg, i) => arg.type === 'Identifier' && arg.name === paramNames[i])
          ) {
            issues.push({
              file: filePath,
              line,
              severity: 'LOW',
              category: 'AI_SLOP_AST',
              type: 'REDUNDANT_WRAPPER',
              message: `Function "${name}" is a redundant 1:1 pass-through wrapper around "${call.callee.name}()". Call "${call.callee.name}" directly.`,
              snippet: getLineText(line)
            });
          }
        }
      }
    });
  } catch {
    // safe fallback
  }

  return issues;
}

export function auditWorkspaceAntiSlop(projectDir = process.cwd()) {
  const files = [];
  function walk(dir) {
    if (!fs.existsSync(dir)) return;
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (IGNORED_DIRS.has(e.name)) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full);
      else if (/\.(js|jsx|ts|tsx|mjs|cjs)$/.test(e.name) && !/\.(test|spec)\./.test(e.name)) files.push(full);
    }
  }
  walk(projectDir);

  const issues = [];
  for (const f of files) {
    const rel = path.relative(projectDir, f).replace(/\\/g, '/');
    try {
      issues.push(...auditAntiSlopAst(fs.readFileSync(f, 'utf-8'), rel));
    } catch {}
  }

  return { scannedFiles: files.length, issues, passed: issues.length === 0 };
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(__filename)) {
  const args = process.argv.slice(2);
  const jsonMode = args.includes('--json');
  const targetDir = args.find(a => !a.startsWith('-')) || process.cwd();
  const report = auditWorkspaceAntiSlop(targetDir);

  if (jsonMode) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.passed ? 0 : 1);
  }

  console.log(`\n${c.cyan}${c.bold}═════ AVEYX: ANTI-SLOP AST RULESET ═════${c.reset}`);
  if (report.passed) {
    console.log(`${c.green}${c.bold}✓ ZERO ANTI-SLOP AST VIOLATIONS${c.reset} across ${report.scannedFiles} files.\n`);
    process.exit(0);
  }
  console.log(`${c.red}${c.bold}✖ FOUND ${report.issues.length} ANTI-SLOP VIOLATION(S):${c.reset}\n`);
  report.issues.forEach((iss, i) => {
    const col = iss.severity === 'HIGH' ? c.red : c.yellow;
    console.log(`  ${i + 1}. [${col}${iss.severity}${c.reset}] ${c.bold}${iss.type}${c.reset} in ${c.cyan}${iss.file}:${iss.line}${c.reset}`);
    console.log(`     ${iss.message}\n`);
  });
  process.exit(1);
}
