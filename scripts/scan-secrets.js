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

const SECRET_CONTEXT_KEY_REGEX = /(?:api[_-]?key|secret|token|password|passwd|pwd|auth|bearer|credential|private[_-]?key|signing[_-]?key|webhook|client[_-]?secret|access[_-]?key)/i;

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
  safeRealpath(path.join(ROOT_DIR, 'tests', 'v4-phase3-p2.test.js'))
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

function isLikelyPlaceholderOrPath(val) {
  if (!val || val.length < 20 || val.length > 256) return true;
  if (/\s/.test(val)) return true;
  if (/^(?:https?:\/\/|\/|\.\/|\.\.\/|data:)/i.test(val)) return true;
  if (/^(?:example|placeholder|your[_-]|changeme|dummy|test[_-]|xxxx|0000|1234)/i.test(val)) return true;
  return false;
}

/**
 * AST-aware Shannon entropy secret scanner for JS/TS files.
 * Inspects VariableDeclarators, ObjectProperties, and Assignments whose key/name signals a secret context.
 */
export function scanAstHighEntropySecrets(code, filePath = 'unknown.ts') {
  const findings = [];
  if (!/\.(js|jsx|ts|tsx|mjs|cjs)$/i.test(filePath)) return findings;

  let ast;
  try {
    ast = parseBabelAst(code);
  } catch {
    return findings;
  }

  const checkValue = (keyName, valNode) => {
    if (!keyName || !SECRET_CONTEXT_KEY_REGEX.test(keyName)) return;
    if (!valNode) return;
    if (valNode.type === 'TSAsExpression' || valNode.type === 'TSSatisfiesExpression' || valNode.type === 'TSNonNullExpression') {
      return checkValue(keyName, valNode.expression);
    }
    if (valNode.type === 'LogicalExpression' && (valNode.operator === '||' || valNode.operator === '??')) {
      checkValue(keyName, valNode.left);
      checkValue(keyName, valNode.right);
      return;
    }
    let strVal = null;
    if (valNode.type === 'StringLiteral') strVal = valNode.value;
    else if (valNode.type === 'TemplateLiteral' && valNode.expressions.length === 0) {
      strVal = valNode.quasis.map(q => q.value.cooked ?? q.value.raw).join('');
    }
    if (!strVal || isLikelyPlaceholderOrPath(strVal)) return;

    const entropy = shannonEntropy(strVal);
    const hasMix = (/[A-Z]/.test(strVal) ? 1 : 0) + (/[a-z]/.test(strVal) ? 1 : 0) + (/[0-9]/.test(strVal) ? 1 : 0) >= 2;
    if (entropy >= 4.2 && hasMix) {
      findings.push({
        file: filePath,
        line: valNode.loc?.start?.line || 1,
        pattern: `High-Entropy AST Secret (${keyName}, H=${entropy.toFixed(2)})`,
        match: `${strVal.slice(0, 6)}...${strVal.slice(-4)}`
      });
    }
  };

  try {
    traverse(ast, {
      VariableDeclarator(p) {
        if (p.node.id?.type === 'Identifier') {
          checkValue(p.node.id.name, p.node.init);
        }
      },
      ObjectProperty(p) {
        const key = p.node.key?.name || p.node.key?.value;
        checkValue(key, p.node.value);
      },
      AssignmentPattern(p) {
        if (p.node.left?.type === 'Identifier') {
          checkValue(p.node.left.name, p.node.right);
        }
      },
      AssignmentExpression(p) {
        let key = null;
        if (p.node.left?.type === 'Identifier') key = p.node.left.name;
        else if (p.node.left?.type === 'MemberExpression') key = p.node.left.property?.name || p.node.left.property?.value;
        checkValue(key, p.node.right);
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

  // Check .env files directly
  if (fileName.startsWith('.env') && fileName !== '.env.example') {
    findings.push({ file: fullPath, pattern: 'Exposed .env File', match: fileName });
  }

  // Check text files
  try {
    const rawContent = fs.readFileSync(fullPath, 'utf-8');
    const content = rawContent.replace(ZERO_WIDTH_REGEX, '');
    const folded = foldStringLiterals(content);

    // Cross-line variable resolution (shared single source of truth from audit-diff.js)
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

    if (!matchedRegex && /\.(js|jsx|ts|tsx|mjs|cjs)$/i.test(fileName)) {
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
          if (stat.isDirectory()) {
            scanDirectory(fullPath, findings, visited);
          } else if (stat.isFile()) {
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
  } catch {
    // ignore unreadable dirs
  }
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
