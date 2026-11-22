#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { builtinModules } from 'node:module';
import { fileURLToPath } from 'node:url';
import { buildDependencyGraph } from './dependency-graph.js';

const __filename = fileURLToPath(import.meta.url);

const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  gray: '\x1b[90m'
};

const NODE_BUILTINS = new Set([
  ...builtinModules,
  ...builtinModules.map(m => (m.startsWith('node:') ? m.slice(5) : `node:${m}`))
]);

const POPULAR_NPM_PACKAGES = [
  'react', 'react-dom', 'next', 'vue', 'svelte', 'express', 'fastify', 'koa', 'hono',
  'axios', 'node-fetch', 'undici', 'lodash', 'underscore', 'ramda', 'zod', 'yup', 'joi',
  'typescript', 'eslint', 'prettier', 'vitest', 'jest', 'mocha', 'chai', 'playwright',
  'tailwindcss', 'postcss', 'autoprefixer', 'prisma', 'drizzle-orm', 'mongoose', 'pg',
  'mysql2', 'sqlite3', 'redis', 'ioredis', 'dotenv', 'chalk', 'commander', 'yargs',
  'inquirer', 'ora', 'uuid', 'nanoid', 'dayjs', 'date-fns', 'moment', 'jsonwebtoken',
  'bcrypt', 'bcryptjs', 'cors', 'helmet', 'multer', 'socket.io', 'ws', 'graphql',
  'apollo-server', 'stripe', 'openai', 'anthropic', '@anthropic-ai/sdk', '@babel/parser',
  '@babel/traverse', '@babel/generator', 'esbuild', 'vite', 'webpack', 'rollup', 'tsx', 'trpc', '@trpc/server', '@trpc/client', 'tanstack-query', '@tanstack/react-query', 'zustand', 'redux', '@reduxjs/toolkit', 'swr', 'framer-motion', 'lucide-react', 'clsx', 'tailwind-merge', 'drizzle-kit', '@biomejs/biome', 'supertest', 'pino', 'winston', 'bullmq', '@supabase/supabase-js', 'firebase', '@aws-sdk/client-s3'
];

const POPULAR_GO_MODULES = [
  "github.com/gin-gonic/gin", "github.com/gorilla/mux", "github.com/stretchr/testify",
  "go.uber.org/zap", "github.com/spf13/cobra", "gorm.io/gorm", "github.com/labstack/echo",
  "github.com/gofiber/fiber", "github.com/go-chi/chi"
];

const POPULAR_RUST_CRATES = [
  "serde", "serde_json", "tokio", "reqwest", "clap", "anyhow", "thiserror", "axum",
  "actix-web", "sqlx", "diesel", "rand", "chrono", "uuid", "tracing", "hyper", "regex"
];

const POPULAR_PYPI_PACKAGES = [
  'requests', 'httpx', 'aiohttp', 'flask', 'fastapi', 'django', 'uvicorn', 'gunicorn',
  'pydantic', 'sqlalchemy', 'alembic', 'pytest', 'numpy', 'pandas', 'scipy', 'scikit-learn',
  'torch', 'transformers', 'openai', 'anthropic', 'langchain', 'boto3', 'pyyaml',
  'python-dotenv', 'cryptography', 'pyjwt', 'celery', 'redis', 'psycopg2', 'pillow', 'polars', 'ruff', 'mypy', 'playwright', 'selenium', 'beautifulsoup4', 'scrapy', 'langgraph', 'litellm'
];

function damerauLevenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  if (Math.abs(m - n) > 2) return 99;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + cost);
      }
    }
  }
  return dp[m][n];
}

export function extractPackageName(importSpec) {
  if (!importSpec || typeof importSpec !== 'string') return null;
  if (importSpec.startsWith('.') || importSpec.startsWith('/')) return null;
  if (importSpec.startsWith('node:') || NODE_BUILTINS.has(importSpec)) return null;
  if (importSpec.startsWith('@')) {
    const parts = importSpec.split('/');
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : importSpec;
  }
  return importSpec.split('/')[0];
}

function findTyposquatMatch(pkgName, popularList) {
  const lower = pkgName.toLowerCase();
  if (popularList.includes(lower)) return null;
  for (const pop of popularList) {
    if (Math.abs(lower.length - pop.length) > 2) continue;
    const dist = damerauLevenshtein(lower, pop);
    if (dist > 0 && dist <= 2 && lower.length >= 4) {
      return pop;
    }
  }
  return null;
}

function readLockfilePackages(projectDir) {
  const locked = new Set();
  let lockfileFound = null;

  const pkgLockPath = path.join(projectDir, 'package-lock.json');
  if (fs.existsSync(pkgLockPath)) {
    lockfileFound = 'package-lock.json';
    try {
      const data = JSON.parse(fs.readFileSync(pkgLockPath, 'utf-8'));
      if (data.packages && typeof data.packages === 'object') {
        for (const key of Object.keys(data.packages)) {
          const idx = key.lastIndexOf('node_modules/');
          if (idx !== -1) locked.add(key.slice(idx + 'node_modules/'.length));
        }
      }
      if (data.dependencies && typeof data.dependencies === 'object') {
        for (const dep of Object.keys(data.dependencies)) locked.add(dep);
      }
    } catch {}
  }

  const pnpmLockPath = path.join(projectDir, 'pnpm-lock.yaml');
  if (!lockfileFound && fs.existsSync(pnpmLockPath)) {
    lockfileFound = 'pnpm-lock.yaml';
    try {
      const raw = fs.readFileSync(pnpmLockPath, 'utf-8');
      for (const m of raw.matchAll(/^\s{2,6}(['"]?)(@?[^:\s'"]+)\1:/gm)) {
        locked.add(m[2]);
      }
    } catch {}
  }

  const yarnLockPath = path.join(projectDir, 'yarn.lock');
  if (!lockfileFound && fs.existsSync(yarnLockPath)) {
    lockfileFound = 'yarn.lock';
    try {
      const raw = fs.readFileSync(yarnLockPath, 'utf-8');
      for (const m of raw.matchAll(/^"?(@?[^@\s",:]+)@/gm)) {
        locked.add(m[1]);
      }
    } catch {}
  }

  return { lockfileFound, locked };
}

/**
 * Offline slopsquatting, hallucinated import, typosquatting, and lockfile drift guard.
 */
export function checkDependencies(projectDir = process.cwd()) {
  const absRoot = path.resolve(projectDir);
  const issues = [];
  const pkgPath = path.join(absRoot, 'package.json');
  const declaredNpm = new Set();

  if (fs.existsSync(pkgPath)) {
    let pkg = {};
    try {
      pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
    } catch {
      issues.push({
        severity: 'HIGH',
        category: 'INVALID_MANIFEST',
        package: 'package.json',
        message: 'Failed to parse package.json.'
      });
    }

    const depSections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
    const directDeps = new Set();
    for (const sec of depSections) {
      if (pkg[sec] && typeof pkg[sec] === 'object') {
        for (const name of Object.keys(pkg[sec])) {
          declaredNpm.add(name);
          const verSpec = pkg[sec][name];
          if (typeof verSpec === "string" && /^file:\.\./i.test(verSpec)) {
            issues.push({
              severity: "HIGH",
              category: "SUSPICIOUS_LOCAL_TRAVERSAL_DEP",
              package: name,
              message: `Package "${name}" references parent directory outside repo: "${verSpec}".`
            });
          }
          if (typeof verSpec === "string" && /^npm:/i.test(verSpec)) {
            const aliased = verSpec.slice(4).replace(/@[^/]+$/, "");
            const aliasTypo = findTyposquatMatch(aliased, POPULAR_NPM_PACKAGES);
            if (aliasTypo) {
              issues.push({
                severity: "CRITICAL",
                category: "SLOPSQUAT_TYPOSQUAT",
                package: `${name} -> ${aliased}`,
                message: `Dependency "${name}" aliases suspicious npm package "${aliased}" (resembles "${aliasTypo}").`
              });
            }
          }
          if (typeof verSpec === "string" && /^(?:git\+)?http:\/\//i.test(verSpec)) {
            issues.push({
              severity: "CRITICAL",
              category: "INSECURE_DEPENDENCY_URL",
              package: name,
              message: `Package "${name}" uses unencrypted HTTP dependency URL: "${verSpec}". Use HTTPS or registry semver.`
            });
          }
          if (sec === 'dependencies' || sec === 'devDependencies') directDeps.add(name);
        }
      }
    }

    // 1. Check lockfile drift (manifest has package missing from lockfile)
    const { lockfileFound, locked } = readLockfilePackages(absRoot);
    if (lockfileFound) {
      for (const dep of directDeps) {
        if (!locked.has(dep)) {
          issues.push({
            severity: 'HIGH',
            category: 'UNVERIFIED_LOCKFILE_DRIFT',
            package: dep,
            message: `Package "${dep}" is declared in package.json but missing from ${lockfileFound} (possible unverified/hallucinated dependency).`
          });
        }
      }
    }

    // 2. Check typosquatting on declared npm packages
    for (const dep of declaredNpm) {
      const similar = findTyposquatMatch(dep, POPULAR_NPM_PACKAGES);
      if (similar) {
        issues.push({
          severity: 'CRITICAL',
          category: 'SLOPSQUAT_TYPOSQUAT',
          package: dep,
          message: `Declared package "${dep}" is suspiciously close (edit distance <= 2) to popular package "${similar}". Verify before installing.`
        });
      }
    }

    // 3. Check suspicious lifecycle scripts in package.json
    if (pkg.scripts && typeof pkg.scripts === 'object') {
      for (const hookName of ['preinstall', 'install', 'postinstall', 'prepare']) {
        const scriptVal = pkg.scripts[hookName];
        if (typeof scriptVal === 'string' && /(?:curl|wget|powershell|eval\(|base64\s+-d|\|\s*(?:sh|bash))/i.test(scriptVal)) {
          issues.push({
            severity: 'CRITICAL',
            category: 'SUSPICIOUS_LIFECYCLE_SCRIPT',
            package: `scripts.${hookName}`,
            message: `Dangerous command pattern in package.json scripts.${hookName}: "${scriptVal.slice(0, 80)}"`
          });
        }
      }
    }

    // 4. Cross-check JS/TS external imports against package.json
    const { externalDeps } = buildDependencyGraph(absRoot);
    const checkedPkgs = new Set();
    for (const rawImp of externalDeps) {
      const pkgName = extractPackageName(rawImp);
      if (!pkgName || checkedPkgs.has(pkgName)) continue;
      checkedPkgs.add(pkgName);

      // Skip if it looks like a Python/Go/Rust module path (only check when package.json is present and not a Go URL)
      if (/^(?:github\.com|golang\.org|gopkg\.in|crate|super|self)\b/.test(pkgName)) continue;

      if (!declaredNpm.has(pkgName) && pkgName !== pkg.name) {
        const typo = findTyposquatMatch(pkgName, POPULAR_NPM_PACKAGES);
        issues.push({
          severity: typo ? 'CRITICAL' : 'HIGH',
          category: typo ? 'SLOPSQUAT_TYPOSQUAT' : 'UNDECLARED_DEPENDENCY',
          package: pkgName,
          message: typo
            ? `Imported package "${pkgName}" is NOT in package.json and closely resembles "${typo}" (possible AI slopsquatting).`
            : `Imported package "${pkgName}" is NOT declared in package.json (possible AI-hallucinated dependency).`
        });
      }
    }
  }

  // 5. Check Python requirements.txt if present
  const reqPath = path.join(absRoot, 'requirements.txt');
  if (fs.existsSync(reqPath)) {
    try {
      const lines = fs.readFileSync(reqPath, 'utf-8').split('\n');
      for (const line of lines) {
        const clean = line.replace(/#.*$/, '').trim();
        if (!clean || clean.startsWith('-')) continue;
        const pkgName = clean.split(/[=<>!~\[\s;]/)[0].trim();
        if (!pkgName) continue;
        const typo = findTyposquatMatch(pkgName, POPULAR_PYPI_PACKAGES);
        if (typo) {
          issues.push({
            severity: 'CRITICAL',
            category: 'SLOPSQUAT_TYPOSQUAT',
            package: pkgName,
            message: `Python requirement "${pkgName}" in requirements.txt closely resembles "${typo}" (possible typosquat/slopsquat).`
          });
        }
      }
    } catch {}
  }

  // 6. Check pyproject.toml if present
  const pyprojPath = path.join(absRoot, "pyproject.toml");
  if (fs.existsSync(pyprojPath)) {
    try {
      const raw = fs.readFileSync(pyprojPath, "utf-8");
      for (const m of raw.matchAll(/"([a-zA-Z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:[=<>!~]|")/g)) {
        const pkgName = m[1];
        const typo = findTyposquatMatch(pkgName, POPULAR_PYPI_PACKAGES);
        if (typo) {
          issues.push({
            severity: "CRITICAL",
            category: "SLOPSQUAT_TYPOSQUAT",
            package: pkgName,
            message: `Python dependency "${pkgName}" in pyproject.toml closely resembles "${typo}" (possible typosquat/slopsquat).`
          });
        }
      }
    } catch {}
  }

  // 7. Check Cargo.toml [dependencies] if present
  const cargoPath = path.join(absRoot, "Cargo.toml");
  if (fs.existsSync(cargoPath)) {
    try {
      const raw = fs.readFileSync(cargoPath, "utf-8");
      const depBlock = raw.match(/\[(?:dev-)?dependencies\]([\s\S]*?)(?=\n\[|$)/g) || [];
      for (const blk of depBlock) {
        for (const m of blk.matchAll(/^\s*([a-zA-Z0-9_-]+)\s*=/gm)) {
          const crateName = m[1];
          const typo = findTyposquatMatch(crateName, POPULAR_RUST_CRATES);
          if (typo) {
            issues.push({
              severity: "CRITICAL",
              category: "SLOPSQUAT_TYPOSQUAT",
              package: crateName,
              message: `Rust crate "${crateName}" in Cargo.toml closely resembles "${typo}" (possible typosquat/slopsquat).`
            });
          }
        }
      }
    } catch {}
  }

  // 8. Check go.mod require entries if present
  const goModPath = path.join(absRoot, "go.mod");
  if (fs.existsSync(goModPath)) {
    try {
      const raw = fs.readFileSync(goModPath, "utf-8");
      for (const m of raw.matchAll(/^\s*(?:require\s+)?([a-zA-Z0-9._-]+\/[a-zA-Z0-9._/-]+)\s+v[0-9]/gm)) {
        const modName = m[1];
        const typo = findTyposquatMatch(modName, POPULAR_GO_MODULES);
        if (typo) {
          issues.push({
            severity: "CRITICAL",
            category: "SLOPSQUAT_TYPOSQUAT",
            package: modName,
            message: `Go module "${modName}" in go.mod closely resembles "${typo}" (possible typosquat).`
          });
        }
      }
    } catch {}
  }

  return {
    passed: issues.length === 0,
    issues,
    declaredCount: declaredNpm.size
  };
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(__filename)) {
  const args = process.argv.slice(2);
  const jsonMode = args.includes('--json');
  const strictMode = args.includes('--strict');
  const targetDir = args.find(a => !a.startsWith('-')) || process.cwd();

  const report = checkDependencies(targetDir);
  if (jsonMode) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.passed ? 0 : 1);
  }

  console.log(`\n${c.cyan}${c.bold}═════ AVEYX: OFFLINE SLOPSQUATTING & DEPENDENCY GUARD ═════${c.reset}`);
  if (report.passed) {
    console.log(`${c.green}${c.bold}✓ ALL DEPENDENCIES VERIFIED${c.reset} (${report.declaredCount} declared packages, 0 anomalies)\n`);
    process.exit(0);
  }

  console.log(`${c.red}${c.bold}✖ FOUND ${report.issues.length} DEPENDENCY RISK(S):${c.reset}\n`);
  report.issues.forEach((iss, i) => {
    const col = iss.severity === 'CRITICAL' ? c.red : c.yellow;
    console.log(`  ${i + 1}. [${col}${iss.severity}${c.reset}] ${c.bold}${iss.category}${c.reset} (${c.cyan}${iss.package}${c.reset})`);
    console.log(`     ${iss.message}\n`);
  });
  if (strictMode || report.issues.some(i => i.severity === 'CRITICAL')) {
    process.exit(1);
  }
}
