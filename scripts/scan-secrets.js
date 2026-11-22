#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import _traverse from '@babel/traverse';
import { parseBabelAst } from './ast-parser.js';
import {
  SECRET_PATTERNS,
  ZERO_WIDTH_REGEX,
  auditDiff,
  foldStringLiterals,
  inspectBase64Payloads,
  resolveLineWithVars
} from './audit-diff.js';

const traverse = _traverse.default || _traverse;

export { foldStringLiterals, inspectBase64Payloads };

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');

const IGNORED_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', '.worktrees', '.agents']);

const SECRET_CONTEXT_KEY_REGEX = /(?:api[_-]?keys?|secrets?|tokens?|passwords?|passwd|pwd|auth(?:orization)?|bearer|credentials?|private[_-]?keys?|signing[_-]?keys?|webhooks?|client[_-]?secrets?|access[_-]?keys?|login)/i;

function safeRealpath(p) {
  try {
    return fs.realpathSync(p);
  } catch {
    return path.resolve(p);
  }
}

const SELF_EXCLUDED_PATHS = new Set([
  safeRealpath(path.join(ROOT_DIR, 'scripts', 'scan-secrets.js')),
  safeRealpath(path.join(ROOT_DIR, 'scripts', 'audit-diff.js')),
  safeRealpath(path.join(ROOT_DIR, 'tests', 'diff-audit.test.js')),
  safeRealpath(path.join(ROOT_DIR, 'tests', 'v3-redteam-regression.test.js')),
  safeRealpath(path.join(ROOT_DIR, 'tests', 'v4-phase2-p1.test.js')),
  safeRealpath(path.join(ROOT_DIR, 'tests', 'v4-phase3-p2.test.js')),
  safeRealpath(path.join(ROOT_DIR, 'tests', 'v4-triple-loop-breaker.test.js')),
  safeRealpath(path.join(ROOT_DIR, 'tests', 'v4-claude-audit-remediation.test.js'))
]);

export function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isLikelySafeNonSecret(val) {
  if (!val || val.length < 20 || val.length > 256) return true;
  if (/^(?:https?:\/\/|\/|\.\/|\.\.\/|data:|sha(?:256|384|512)-)/i.test(val)) return true;
  if (/^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i.test(val)) return true; // pure hex MD5/SHA1/SHA256
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(val)) return true; // UUID
  if (/^(?:example|placeholder|your[_-]|changeme|dummy|test[_-]|xxxx|0000|1234)/i.test(val)) return true;
  if (/\s/.test(val)) return true;
  // Reject pure alphabetic multi-word CamelCase identifiers (e.g. thisIsAVeryLongCamelCaseIdentifier)
  if (/^[A-Za-z]+$/.test(val) && (val.match(/[a-z][A-Z]/g) || []).length >= 3) return true;
  return false;
}

function resolveAstString(node) {
  if (!node) return null;
  if (node.type === 'TSAsExpression' || node.type === 'TSSatisfiesExpression' || node.type === 'TSNonNullExpression') {
    return resolveAstString(node.expression);
  }
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis.map(q => q.value.cooked ?? q.value.raw).join('');
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const l = resolveAstString(node.left);
    const r = resolveAstString(node.right);
    if (l !== null && r !== null) return l + r;
    return null;
  }
  if (node.type === 'CallExpression') {
    // ["a","b"].join("")
    if (node.callee?.type === 'MemberExpression' && node.callee.property?.name === 'join' && node.callee.object?.type === 'ArrayExpression') {
      const sep = node.arguments.length > 0 ? resolveAstString(node.arguments[0]) : ',';
      if (sep === null) return null;
      const parts = [];
      for (const el of node.callee.object.elements || []) {
        const v = resolveAstString(el);
        if (v === null) return null;
        parts.push(v);
      }
      return parts.join(sep);
    }
    // atob("...")
    if (node.callee?.type === 'Identifier' && node.callee.name === 'atob' && node.arguments.length === 1) {
      const b64 = resolveAstString(node.arguments[0]);
      if (b64) {
        try { return Buffer.from(b64, 'base64').toString('utf-8'); } catch {}
      }
    }
    // String.fromCharCode(...)
    if (node.callee?.type === 'MemberExpression' && node.callee.object?.name === 'String' && node.callee.property?.name === 'fromCharCode') {
      const nums = (node.arguments || []).map(a => (a?.type === 'NumericLiteral' ? a.value : null));
      if (nums.length >= 12 && nums.every(n => typeof n === 'number')) {
        return String.fromCharCode(...nums);
      }
    }
    // Buffer.from("...", "base64").toString()
    if (
      node.callee?.type === 'MemberExpression' &&
      node.callee.property?.name === 'toString' &&
      node.callee.object?.type === 'CallExpression' &&
      node.callee.object.callee?.type === 'MemberExpression' &&
      node.callee.object.callee.object?.name === 'Buffer' &&
      node.callee.object.callee.property?.name === 'from'
    ) {
      const b64 = resolveAstString(node.callee.object.arguments?.[0]);
      const enc = resolveAstString(node.callee.object.arguments?.[1]);
      if (b64 && enc === 'base64') {
        try { return Buffer.from(b64, 'base64').toString('utf-8'); } catch {}
      }
    }
  }
  return null;
}

/**
 * AST-aware Shannon entropy & obfuscated secret scanner for JS/TS, Python, and JSON files.
 * Inspects declarators, arrays, class fields, object properties, Authorization Bearer headers,
 * call arguments (client.auth("...")), default params, and folded concat/join/atob/fromCharCode strings.
 */
export function scanAstHighEntropySecrets(code, filePath = 'unknown.ts') {
  const findings = [];
  const seen = new Set();

  const recordIfSecret = (keyName, rawVal, line, forceRegexOnly = false) => {
    if (!rawVal || typeof rawVal !== 'string') return;
    // Strip Bearer prefix for Authorization header values
    const val = /^Bearer\s+/i.test(rawVal) ? rawVal.replace(/^Bearer\s+/i, '').trim() : rawVal;

    // 1. Direct known secret pattern match (even on bare names like `const x = "sk_live_..."`)
    for (const sp of SECRET_PATTERNS) {
      if (sp.regex.test(val)) {
        const sig = `${line}:${val.slice(0, 10)}`;
        if (!seen.has(sig)) {
          seen.add(sig);
          findings.push({
            file: filePath,
            line,
            pattern: `AST ${sp.name}${keyName ? ` (${keyName})` : ''}`,
            match: `${val.slice(0, 6)}...${val.slice(-4)}`
          });
        }
        return;
      }
    }

    if (forceRegexOnly) return;
    if (!keyName || !SECRET_CONTEXT_KEY_REGEX.test(keyName)) return;
    if (isLikelySafeNonSecret(val)) return;

    const entropy = shannonEntropy(val);
    const hasMix = (/[A-Z]/.test(val) ? 1 : 0) + (/[a-z]/.test(val) ? 1 : 0) + (/[0-9]/.test(val) ? 1 : 0) >= 2;
    if (entropy >= 4.0 && hasMix) {
      const sig = `${line}:${val.slice(0, 10)}`;
      if (!seen.has(sig)) {
        seen.add(sig);
        findings.push({
          file: filePath,
          line,
          pattern: `High-Entropy AST Secret (${keyName}, H=${entropy.toFixed(2)})`,
          match: `${val.slice(0, 6)}...${val.slice(-4)}`
        });
      }
    }
  };

  // Non-JS/TS fallback (.py, .json, .yaml, .toml)
  if (!/\.(js|jsx|ts|tsx|mjs|cjs)$/i.test(filePath)) {
    const lines = String(code || '').split('\n');
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(/['"]?([A-Za-z0-9_-]{3,40})['"]?\s*[:=]\s*['"]([^'"]{20,})['"]/);
      if (m) recordIfSecret(m[1], m[2], i + 1, false);
    }
    return findings;
  }

  let ast;
  try {
    ast = parseBabelAst(code);
  } catch {
    return findings;
  }

  const checkNode = (keyName, valNode, forceRegexOnly = false) => {
    if (!valNode) return;
    if (valNode.type === 'TSAsExpression' || valNode.type === 'TSSatisfiesExpression' || valNode.type === 'TSNonNullExpression') {
      return checkNode(keyName, valNode.expression, forceRegexOnly);
    }
    if (valNode.type === 'LogicalExpression' && (valNode.operator === '||' || valNode.operator === '??')) {
      checkNode(keyName, valNode.left, forceRegexOnly);
      checkNode(keyName, valNode.right, forceRegexOnly);
      return;
    }
    if (valNode.type === 'ArrayExpression') {
      for (const el of valNode.elements || []) checkNode(keyName, el, forceRegexOnly);
      return;
    }
    const resolved = resolveAstString(valNode);
    if (resolved !== null) {
      recordIfSecret(keyName, resolved, valNode.loc?.start?.line || 1, forceRegexOnly);
    }
  };

  try {
    traverse(ast, {
      VariableDeclarator(p) {
        if (p.node.id?.type === 'Identifier') {
          checkNode(p.node.id.name, p.node.init, !SECRET_CONTEXT_KEY_REGEX.test(p.node.id.name));
        }
      },
      ClassProperty(p) {
        const key = p.node.key?.name || p.node.key?.value;
        checkNode(key, p.node.value, !SECRET_CONTEXT_KEY_REGEX.test(key || ''));
      },
      ObjectProperty(p) {
        const key = p.node.key?.name || p.node.key?.value;
        checkNode(key, p.node.value, !SECRET_CONTEXT_KEY_REGEX.test(key || ''));
      },
      AssignmentPattern(p) {
        if (p.node.left?.type === 'Identifier') {
          checkNode(p.node.left.name, p.node.right, !SECRET_CONTEXT_KEY_REGEX.test(p.node.left.name));
        }
      },
      AssignmentExpression(p) {
        let key = null;
        if (p.node.left?.type === 'Identifier') key = p.node.left.name;
        else if (p.node.left?.type === 'MemberExpression') key = p.node.left.property?.name || p.node.left.property?.value;
        checkNode(key, p.node.right, !SECRET_CONTEXT_KEY_REGEX.test(key || ''));
      },
      CallExpression(p) {
        let calleeName = '';
        if (p.node.callee?.type === 'Identifier') calleeName = p.node.callee.name;
        else if (p.node.callee?.type === 'MemberExpression') calleeName = p.node.callee.property?.name || '';
        if (SECRET_CONTEXT_KEY_REGEX.test(calleeName)) {
          for (const arg of p.node.arguments || []) {
            checkNode(calleeName, arg, false);
          }
        }
      }
    });
  } catch {
    // safe fallback
  }

  return findings;
}

/**
 * Sweeps unpushed git commits (`@{u}..HEAD`, or local commits not on any remote) for leaked secrets.
 */
export function scanUnpushedCommits(repoDir = process.cwd()) {
  const absRoot = path.resolve(repoDir);
  const findings = [];
  let rawLog = '';

  const tryGitLog = (rangeArgs) => {
    try {
      return execFileSync('git', ['log', ...rangeArgs, '-p', '--format=AVEYX_COMMIT:%H'], {
        cwd: absRoot,
        encoding: 'utf-8',
        maxBuffer: 15 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'ignore']
      });
    } catch {
      return null;
    }
  };

  rawLog = tryGitLog(['@{u}..HEAD']);
  if (rawLog === null) {
    rawLog = tryGitLog(['--branches', '--not', '--remotes', '-n', '25']);
  }
  if (!rawLog || !rawLog.trim()) {
    return { commitsScanned: 0, findings };
  }

  const blocks = rawLog.split(/^AVEYX_COMMIT:/m).filter(Boolean);
  for (const block of blocks) {
    const nl = block.indexOf('\n');
    const sha = (nl === -1 ? block : block.slice(0, nl)).trim();
    const diffBody = nl === -1 ? '' : block.slice(nl + 1);
    if (!diffBody.trim()) continue;

    const audited = auditDiff(diffBody);
    for (const iss of audited.issues) {
      if (iss.category === 'SECRET_LEAK') {
        findings.push({
          commit: sha.slice(0, 8),
          file: iss.file,
          pattern: iss.description,
          match: iss.snippet || ''
        });
      }
    }
  }

  return { commitsScanned: blocks.length, findings };
}

function scanFile(fullPath, fileName, findings) {
  const realFile = safeRealpath(fullPath);
  if (SELF_EXCLUDED_PATHS.has(realFile)) return;

  if (fileName.startsWith('.env') && fileName !== '.env.example') {
    findings.push({ file: fullPath, pattern: 'Exposed .env File', match: fileName });
  }

  try {
    const rawContent = fs.readFileSync(fullPath, 'utf-8');
    const content = rawContent.replace(ZERO_WIDTH_REGEX, '');
    const folded = foldStringLiterals(content);

    const fileStringVars = new Map();
    const resolvedLines = rawContent.split('\n').map(l => resolveLineWithVars(l, fileStringVars).resolved);
    const resolvedContent = resolvedLines.join('\n');

    let matchedRegex = false;
    for (const { name, regex } of SECRET_PATTERNS) {
      const match = regex.exec(content) || regex.exec(folded) || regex.exec(resolvedContent);
      if (match) {
        const matchedText = match[0];
        const masked = matchedText.slice(0, 7) + '...' + matchedText.slice(-4);
        findings.push({ file: fullPath, pattern: name, match: masked });
        matchedRegex = true;
        break;
      }
    }

    const b64 = inspectBase64Payloads(content) || inspectBase64Payloads(folded) || inspectBase64Payloads(resolvedContent);
    if (b64) {
      findings.push({ file: fullPath, pattern: 'Base64 Encoded Credential Payload', match: b64.matched.slice(0, 8) + '...' });
    }

    if (!matchedRegex && /\.(js|jsx|ts|tsx|mjs|cjs|py|json)$/i.test(fileName)) {
      const astEntropyHits = scanAstHighEntropySecrets(rawContent, fullPath);
      findings.push(...astEntropyHits);
    }
  } catch {
    // Binary or unreadable files skipped safely
  }
}

export function scanDirectory(dir, findings = [], visited = new Set()) {
  if (!fs.existsSync(dir)) return findings;
  try {
    const realDir = fs.realpathSync(dir);
    if (visited.has(realDir)) return findings;
    visited.add(realDir);

    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (IGNORED_DIRS.has(entry.name)) continue;
      const fullPath = path.join(dir, entry.name);

      if (entry.isSymbolicLink()) {
        try {
          const target = fs.realpathSync(fullPath);
          if (visited.has(target)) continue;
          const stat = fs.statSync(fullPath);
          if (stat.isDirectory()) scanDirectory(fullPath, findings, visited);
          else if (stat.isFile()) {
            visited.add(target);
            scanFile(fullPath, entry.name, findings);
          }
        } catch {
          continue;
        }
      } else if (entry.isDirectory()) {
        scanDirectory(fullPath, findings, visited);
      } else if (entry.isFile()) {
        scanFile(fullPath, entry.name, findings);
      }
    }
  } catch {}
  return findings;
}

if (process.argv[1] && safeRealpath(process.argv[1]) === safeRealpath(__filename)) {
  const args = process.argv.slice(2);
  const checkUnpushed = args.includes('--unpushed');
  const targetDir = args.find(a => !a.startsWith('-')) || process.cwd();
  if (!fs.existsSync(targetDir) || !fs.statSync(targetDir).isDirectory()) {
    console.error(`\x1b[31mError: Target path does not exist or is not a directory: ${targetDir}\x1b[0m`);
    process.exit(1);
  }
  console.log(`[Aveyx] Scanning for leaked credentials in: ${targetDir}...`);
  const findings = scanDirectory(targetDir);

  if (checkUnpushed) {
    const unpushed = scanUnpushedCommits(targetDir);
    console.log(`[Aveyx] Swept ${unpushed.commitsScanned} unpushed git commit(s)...`);
    for (const f of unpushed.findings) {
      findings.push({ file: `${f.file} (commit ${f.commit})`, pattern: f.pattern, match: f.match });
    }
  }

  if (findings.length === 0) {
    console.log(`\x1b[32m✓ Zero leaked credentials found. Repository is clean.\x1b[0m`);
    process.exit(0);
  } else {
    console.error(`\x1b[31m⚠️ CRITICAL: Found ${findings.length} potential secret leak(s)!\x1b[0m`);
    for (const f of findings) {
      console.error(`  - \x1b[33m${f.pattern}\x1b[0m in \x1b[36m${f.file}\x1b[0m: ${f.match}`);
    }
    process.exit(1);
  }
}
