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
const EXEMPT_STUB_NAMES = /^(?:noop|_noop|identity)$/i;

// Strict suppression format: `aveyx-ignore <RULE_ID>: <reason >= 15 chars>`
const STRICT_IGNORE_RE = /\baveyx-ignore\s+([A-Z0-9_]+)\s*:\s*(.{15,})/i;

function isNullishOrEmptyLiteral(node) {
  if (!node) return true;
  if (node.type === 'NullLiteral' || node.type === 'BooleanLiteral') return true;
  if (node.type === 'Identifier' && node.name === 'undefined') return true;
  if (node.type === 'UnaryExpression' && node.operator === 'void') return true;
  if (node.type === 'ObjectExpression' && node.properties.length === 0) return true;
  if (node.type === 'ArrayExpression' && node.elements.length === 0) return true;
  return false;
}

function isNoOpStatement(stmt) {
  if (!stmt) return true;
  if (stmt.type === 'EmptyStatement') return true;
  if (stmt.type === 'ExpressionStatement') {
    const ex = stmt.expression;
    if (ex.type === 'Identifier') return true; // bare `e;`
    if (ex.type === 'UnaryExpression' && ex.operator === 'void') return true; // `void e;`
    // Log-only catch body: console.log(e) / console.warn(e) / console.error(e) with no recovery
    if (
      ex.type === 'CallExpression' &&
      ex.callee?.type === 'MemberExpression' &&
      ex.callee.object?.name === 'console' &&
      ['log', 'warn', 'error', 'debug', 'info'].includes(ex.callee.property?.name)
    ) {
      return true;
    }
  }
  return false;
}

function isSilentHandlerFn(fnNode) {
  if (!fnNode || (fnNode.type !== 'ArrowFunctionExpression' && fnNode.type !== 'FunctionExpression')) return false;
  if (fnNode.body?.type === 'BlockStatement') {
    const stmts = fnNode.body.body;
    if (stmts.length === 0) return true;
    if (stmts.every(isNoOpStatement)) return true;
    if (stmts.length === 1 && stmts[0].type === 'ReturnStatement' && isNullishOrEmptyLiteral(stmts[0].argument)) return true;
    return false;
  }
  return isNullishOrEmptyLiteral(fnNode.body);
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
 * - EMPTY_CATCH_BLOCK (empty, void e, bare e, log-only catch)
 * - SILENT_ERROR_MASKING (catch returning null/undefined/bool/{}/[])
 * - FINALLY_RETURN_SWALLOW (return inside finally swallowing thrown errors)
 * - SILENT_PROMISE_SWALLOW (.catch(() => {}) and .then(ok, () => {}))
 * - EMPTY_STUB_FUNCTION (exported functions, exported arrows, empty class methods, return-only stubs)
 * - REDUNDANT_WRAPPER (sync and async 1:1 pass-through wrappers)
 * - DEAD_CODE_BRANCH (constant-falsy if/while branches via AST evaluation)
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
  const allComments = Array.isArray(ast.comments) ? ast.comments : [];
  const getLineText = (line) => (lines[(line || 1) - 1] || '').trim().slice(0, 80);

  // Check ONLY real AST comment nodes on the same line, inside the node, or on the immediately preceding line.
  const isSuppressed = (node, ruleType) => {
    const startLine = node.loc?.start?.line || 1;
    const endLine = node.loc?.end?.line || startLine;
    for (const cm of allComments) {
      const cStart = cm.loc?.start?.line || 0;
      const cEnd = cm.loc?.end?.line || 0;
      const adjacent = (cEnd === startLine - 1) || (cStart >= startLine && cEnd <= endLine);
      if (!adjacent) continue;
      const m = STRICT_IGNORE_RE.exec(cm.value || '');
      if (m && (m[1].toUpperCase() === ruleType || m[1].toUpperCase() === 'ALL')) {
        return true;
      }
    }
    return false;
  };

  const checkWrapperOrStub = (name, fnNode, isExported, line) => {
    if (name && EXEMPT_STUB_NAMES.test(name)) return;
    if (!fnNode?.body) return;

    if (fnNode.body.type !== 'BlockStatement') {
      if (isExported && isNullishOrEmptyLiteral(fnNode.body) && !isSuppressed(fnNode, 'EMPTY_STUB_FUNCTION')) {
        issues.push({
          file: filePath,
          line,
          severity: 'HIGH',
          category: 'AI_SLOP_AST',
          type: 'EMPTY_STUB_FUNCTION',
          message: `Exported function "${name || 'default'}" returns only a constant nullish/empty stub.`,
          snippet: getLineText(line)
        });
      }
      return;
    }

    const body = fnNode.body.body || [];
    const isEmptyOrBareReturn = body.length === 0 || (body.length === 1 && body[0].type === 'ReturnStatement' && !body[0].argument);
    if (isExported && isEmptyOrBareReturn && !isSuppressed(fnNode, 'EMPTY_STUB_FUNCTION')) {
      issues.push({
        file: filePath,
        line,
        severity: 'HIGH',
        category: 'AI_SLOP_AST',
        type: 'EMPTY_STUB_FUNCTION',
        message: `Exported function "${name || 'default'}" has an empty/no-op body (unimplemented stub).`,
        snippet: getLineText(line)
      });
      return;
    }

    // Redundant 1:1 wrapper (sync or async): function foo(a) { return bar(a); } / async function foo(a) { return await bar(a); }
    if (!isExported && body.length === 1 && body[0].type === 'ReturnStatement' && body[0].argument) {
      let retExpr = body[0].argument;
      if (retExpr.type === 'AwaitExpression') retExpr = retExpr.argument;
      if (retExpr?.type === 'CallExpression' && retExpr.callee?.type === 'Identifier' && retExpr.callee.name !== name) {
        const paramNames = getParamNames(fnNode.params);
        if (
          paramNames &&
          paramNames.length > 0 &&
          retExpr.arguments.length === paramNames.length &&
          retExpr.arguments.every((arg, i) => arg.type === 'Identifier' && arg.name === paramNames[i]) &&
          !isSuppressed(fnNode, 'REDUNDANT_WRAPPER')
        ) {
          issues.push({
            file: filePath,
            line,
            severity: 'LOW',
            category: 'AI_SLOP_AST',
            type: 'REDUNDANT_WRAPPER',
            message: `Function "${name}" is a redundant 1:1 pass-through wrapper around "${retExpr.callee.name}()".`,
            snippet: getLineText(line)
          });
        }
      }
    }
  };

  try {
    traverse(ast, {
      IfStatement(p) {
        const line = p.node.loc?.start?.line || 1;
        const evalRes = p.get('test').evaluate();
        if (evalRes.confident && !evalRes.value && !isSuppressed(p.node, 'DEAD_CODE_BRANCH')) {
          issues.push({
            file: filePath,
            line,
            severity: 'MEDIUM',
            category: 'AI_SLOP_AST',
            type: 'DEAD_CODE_BRANCH',
            message: 'Unreachable constant-falsy "if (...)" dead branch left in code.',
            snippet: getLineText(line)
          });
        }
      },

      WhileStatement(p) {
        const line = p.node.loc?.start?.line || 1;
        const evalRes = p.get('test').evaluate();
        if (evalRes.confident && !evalRes.value && !isSuppressed(p.node, 'DEAD_CODE_BRANCH')) {
          issues.push({
            file: filePath,
            line,
            severity: 'MEDIUM',
            category: 'AI_SLOP_AST',
            type: 'DEAD_CODE_BRANCH',
            message: 'Unreachable constant-falsy "while (...)" dead loop left in code.',
            snippet: getLineText(line)
          });
        }
      },

      TryStatement(p) {
        if (p.node.finalizer?.body) {
          const retStmt = p.node.finalizer.body.find(s => s.type === 'ReturnStatement');
          if (retStmt && !isSuppressed(p.node.finalizer, 'FINALLY_RETURN_SWALLOW')) {
            const line = retStmt.loc?.start?.line || p.node.finalizer.loc?.start?.line || 1;
            issues.push({
              file: filePath,
              line,
              severity: 'HIGH',
              category: 'AI_SLOP_AST',
              type: 'FINALLY_RETURN_SWALLOW',
              message: 'Return statement inside finally {} silently overrides thrown exceptions.',
              snippet: getLineText(line)
            });
          }
        }
      },

      CatchClause(p) {
        const body = p.node.body?.body || [];
        const line = p.node.loc?.start?.line || 1;

        if (body.length === 0 || body.every(isNoOpStatement)) {
          if (!isSuppressed(p.node, 'EMPTY_CATCH_BLOCK') && !isSuppressed(p.parentPath.node, 'EMPTY_CATCH_BLOCK')) {
            issues.push({
              file: filePath,
              line,
              severity: 'HIGH',
              category: 'AI_SLOP_AST',
              type: 'EMPTY_CATCH_BLOCK',
              message: 'Catch block silently swallows exception (empty, no-op, or log-only without recovery/rethrow).',
              snippet: getLineText(line)
            });
          }
          return;
        }

        if (body.length === 1 && body[0].type === 'ReturnStatement' && isNullishOrEmptyLiteral(body[0].argument)) {
          if (!isSuppressed(p.node, 'SILENT_ERROR_MASKING') && !isSuppressed(p.parentPath.node, 'SILENT_ERROR_MASKING')) {
            issues.push({
              file: filePath,
              line,
              severity: 'MEDIUM',
              category: 'AI_SLOP_AST',
              type: 'SILENT_ERROR_MASKING',
              message: 'Catch block masks failure by silently returning null/undefined/boolean/empty literal.',
              snippet: getLineText(line)
            });
          }
        }
      },

      CallExpression(p) {
        const callee = p.node.callee;
        if (callee?.type === 'MemberExpression') {
          const prop = callee.property?.name;
          const line = p.node.loc?.start?.line || 1;
          if (prop === 'catch' && p.node.arguments.length >= 1 && isSilentHandlerFn(p.node.arguments[0])) {
            if (!isSuppressed(p.node, 'SILENT_PROMISE_SWALLOW')) {
              issues.push({
                file: filePath,
                line,
                severity: 'HIGH',
                category: 'AI_SLOP_AST',
                type: 'SILENT_PROMISE_SWALLOW',
                message: 'Promise .catch() silently swallows rejection without handling or rethrowing.',
                snippet: getLineText(line)
              });
            }
          } else if (prop === 'then' && p.node.arguments.length >= 2 && isSilentHandlerFn(p.node.arguments[1])) {
            if (!isSuppressed(p.node, 'SILENT_PROMISE_SWALLOW')) {
              issues.push({
                file: filePath,
                line,
                severity: 'HIGH',
                category: 'AI_SLOP_AST',
                type: 'SILENT_PROMISE_SWALLOW',
                message: 'Promise .then(onFulfilled, onRejected) silently swallows rejection in second handler.',
                snippet: getLineText(line)
              });
            }
          }
        }
      },

      ClassMethod(p) {
        const name = p.node.key?.name || p.node.key?.value;
        if (p.node.kind === 'constructor' || (name && EXEMPT_STUB_NAMES.test(name))) return;
        const body = p.node.body?.body || [];
        if (body.length === 0 && !isSuppressed(p.node, 'EMPTY_STUB_FUNCTION')) {
          const line = p.node.loc?.start?.line || 1;
          issues.push({
            file: filePath,
            line,
            severity: 'MEDIUM',
            category: 'AI_SLOP_AST',
            type: 'EMPTY_STUB_FUNCTION',
            message: `Class method "${name || 'anonymous'}()" has an empty body (unimplemented stub).`,
            snippet: getLineText(line)
          });
        }
      },

      VariableDeclarator(p) {
        const isExported = Boolean(p.parentPath?.parentPath?.isExportNamedDeclaration?.());
        const init = p.node.init;
        if (
          p.node.id?.type === 'Identifier' &&
          init &&
          (init.type === 'ArrowFunctionExpression' || init.type === 'FunctionExpression')
        ) {
          checkWrapperOrStub(p.node.id.name, init, isExported, p.node.loc?.start?.line || 1);
        }
      },

      FunctionDeclaration(p) {
        const isExported = Boolean(p.parentPath?.isExportNamedDeclaration() || p.parentPath?.isExportDefaultDeclaration());
        checkWrapperOrStub(p.node.id?.name, p.node, isExported, p.node.loc?.start?.line || 1);
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
