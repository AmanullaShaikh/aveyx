#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { parse } from '@babel/parser';
import * as t from '@babel/traverse';

const traverse = t.default?.default || t.default;

const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  magenta: '\x1b[35m',
  gray: '\x1b[90m'
};

const IGNORED = new Set(['node_modules', '.git', 'dist', 'build', '.next', '.agents', '.worktrees', 'coverage']);


const workspacePkgCache = new Map();

export function loadWorkspacePackages(rootDir) {
  const absRoot = path.resolve(rootDir);
  if (workspacePkgCache.has(absRoot)) return workspacePkgCache.get(absRoot);

  const pkgMap = new Map(); // pkgName -> abs entry path
  const patterns = [];

  const rootPkgPath = path.join(absRoot, "package.json");
  if (fs.existsSync(rootPkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(rootPkgPath, "utf-8"));
      if (Array.isArray(pkg.workspaces)) patterns.push(...pkg.workspaces);
      else if (Array.isArray(pkg.workspaces?.packages)) patterns.push(...pkg.workspaces.packages);
    } catch {}
  }

  const pnpmWsPath = path.join(absRoot, "pnpm-workspace.yaml");
  if (fs.existsSync(pnpmWsPath)) {
    try {
      const raw = fs.readFileSync(pnpmWsPath, "utf-8");
      for (const m of raw.matchAll(/^\s*-\s*['"]?([^\s'"#]+)['"]?/gm)) {
        patterns.push(m[1]);
      }
    } catch {}
  }

  for (const pat of patterns) {
    const clean = pat.replace(/\/\*\*?$/, "").replace(/\/+$/, "");
    const baseDir = path.join(absRoot, clean);
    if (!fs.existsSync(baseDir) || !fs.statSync(baseDir).isDirectory()) continue;
    for (const entry of fs.readdirSync(baseDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const subDir = path.join(baseDir, entry.name);
      const subPkg = path.join(subDir, "package.json");
      if (!fs.existsSync(subPkg)) continue;
      try {
        const meta = JSON.parse(fs.readFileSync(subPkg, "utf-8"));
        if (!meta.name) continue;
        const entryRel = typeof meta.main === "string" ? meta.main : "src/index.ts";
        pkgMap.set(meta.name, { dir: subDir, entry: path.resolve(subDir, entryRel) });
      } catch {}
    }
  }

  workspacePkgCache.set(absRoot, pkgMap);
  return pkgMap;
}

const tsConfigCache = new Map();

function stripJsonCommentsAndTrailingCommas(raw) {
  let out = "";
  let inStr = false;
  let escaped = false;
  let inLineComment = false;
  let inBlockComment = false;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    const next = raw[i + 1];
    if (inLineComment) {
      if (ch === "\n") {
        inLineComment = false;
        out += ch;
      }
      continue;
    }
    if (inBlockComment) {
      if (ch === "*" && next === "/") {
        inBlockComment = false;
        i++;
      }
      continue;
    }
    if (inStr) {
      out += ch;
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === '"') {
        inStr = false;
      }
      continue;
    }
    if (ch === '"') {
      inStr = true;
      out += ch;
      continue;
    }
    if (ch === "/" && next === "/") {
      inLineComment = true;
      i++;
      continue;
    }
    if (ch === "/" && next === "*") {
      inBlockComment = true;
      i++;
      continue;
    }
    out += ch;
  }
  return out.replace(/,\s*([}\]])/g, "$1");
}

function readJsonConfigWithExtends(configPath, depth = 0) {
  if (depth > 3 || !fs.existsSync(configPath)) return null;
  try {
    const raw = fs.readFileSync(configPath, "utf-8");
    const parsed = JSON.parse(stripJsonCommentsAndTrailingCommas(raw));
    let baseOptions = {};
    if (typeof parsed.extends === "string" && parsed.extends.startsWith(".")) {
      let extPath = path.resolve(path.dirname(configPath), parsed.extends);
      if (!fs.existsSync(extPath) && fs.existsSync(extPath + ".json")) extPath += ".json";
      const parent = readJsonConfigWithExtends(extPath, depth + 1);
      if (parent) baseOptions = parent;
    }
    const own = parsed.compilerOptions || {};
    return {
      ...baseOptions,
      ...own,
      paths: { ...(baseOptions.paths || {}), ...(own.paths || {}) }
    };
  } catch {
    return null;
  }
}

export function loadTsConfigPaths(rootDir) {
  const absRoot = path.resolve(rootDir);
  const candidates = ["tsconfig.json", "jsconfig.json"];
  let configPath = null;
  let mtimeMs = 0;
  for (const name of candidates) {
    const p = path.join(absRoot, name);
    if (fs.existsSync(p)) {
      configPath = p;
      try { mtimeMs = fs.statSync(p).mtimeMs; } catch {}
      break;
    }
  }
  if (!configPath) return { hasBaseUrl: false, baseDir: absRoot, paths: [] };

  const cached = tsConfigCache.get(absRoot);
  if (cached && cached.configPath === configPath && cached.mtimeMs === mtimeMs) {
    return cached.data;
  }

  const opts = readJsonConfigWithExtends(configPath) || {};
  const hasBaseUrl = typeof opts.baseUrl === "string" && opts.baseUrl.length > 0;
  const baseDir = hasBaseUrl ? path.resolve(absRoot, opts.baseUrl) : absRoot;
  const rawPaths = opts.paths && typeof opts.paths === "object" ? opts.paths : {};
  const compiledPaths = [];

  for (const [pattern, targets] of Object.entries(rawPaths)) {
    if (!Array.isArray(targets)) continue;
    const starIdx = pattern.indexOf("*");
    compiledPaths.push({
      pattern,
      hasStar: starIdx !== -1,
      prefix: starIdx !== -1 ? pattern.slice(0, starIdx) : pattern,
      suffix: starIdx !== -1 ? pattern.slice(starIdx + 1) : "",
      targets: targets.filter(t => typeof t === "string")
    });
  }
  // Sort longest prefix first for deterministic specificity
  compiledPaths.sort((a, b) => b.prefix.length - a.prefix.length);

  const data = { hasBaseUrl, baseDir, paths: compiledPaths };
  tsConfigCache.set(absRoot, { configPath, mtimeMs, data });
  return data;
}

function tryResolveFileOnDisk(resolvedAbs, rootDir) {
  const extensions = ['', '.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs', '/index.ts', '/index.js', '/index.tsx', '/index.jsx'];
  for (const ext of extensions) {
    const candidate = resolvedAbs + ext;
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
      return path.relative(rootDir, candidate).replace(/\\/g, '/');
    }
  }

  // NodeNext TypeScript ESM convention: import './bar.js' -> resolves to bar.ts / bar.tsx
  const esmExtMap = [
    [/\.js$/i, ['.ts', '.tsx']],
    [/\.jsx$/i, ['.tsx']],
    [/\.mjs$/i, ['.mts']],
    [/\.cjs$/i, ['.cts']]
  ];
  for (const [pattern, tsExts] of esmExtMap) {
    if (pattern.test(resolvedAbs)) {
      const base = resolvedAbs.replace(pattern, '');
      for (const tsExt of tsExts) {
        const candidate = base + tsExt;
        if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
          return path.relative(rootDir, candidate).replace(/\\/g, '/');
        }
      }
    }
  }
  return null;
}

export function resolveImportPath(sourceFile, importString, rootDir, tsConfig = null) {
  if (!importString.startsWith('.')) {
    const cfg = tsConfig || loadTsConfigPaths(rootDir);
    for (const rule of cfg.paths) {
      let matched = false;
      let wildcard = "";
      if (rule.hasStar) {
        if (importString.startsWith(rule.prefix) && importString.endsWith(rule.suffix) && importString.length >= rule.prefix.length + rule.suffix.length) {
          matched = true;
          wildcard = importString.slice(rule.prefix.length, importString.length - rule.suffix.length);
        }
      } else if (importString === rule.pattern) {
        matched = true;
      }
      if (matched) {
        for (const target of rule.targets) {
          const mapped = rule.hasStar ? target.split("*").join(wildcard) : target;
          const candidateAbs = path.resolve(cfg.baseDir, mapped);
          const hit = tryResolveFileOnDisk(candidateAbs, rootDir);
          if (hit) return { type: 'internal', path: hit };
        }
      }
    }
    // Monorepo workspace package cross-linking (@acme/shared or @acme/shared/utils)
    const wsPkgs = loadWorkspacePackages(rootDir);
    if (wsPkgs.size > 0) {
      for (const [pkgName, info] of wsPkgs.entries()) {
        if (importString === pkgName) {
          const hit = tryResolveFileOnDisk(info.entry, rootDir) || tryResolveFileOnDisk(path.join(info.dir, "src/index"), rootDir) || tryResolveFileOnDisk(path.join(info.dir, "index"), rootDir);
          if (hit) return { type: 'internal', path: hit };
        } else if (importString.startsWith(pkgName + "/")) {
          const sub = importString.slice(pkgName.length + 1);
          const hit = tryResolveFileOnDisk(path.join(info.dir, sub), rootDir) || tryResolveFileOnDisk(path.join(info.dir, "src", sub), rootDir);
          if (hit) return { type: 'internal', path: hit };
        }
      }
    }
    if (cfg.hasBaseUrl) {
      const candidateAbs = path.resolve(cfg.baseDir, importString);
      const hit = tryResolveFileOnDisk(candidateAbs, rootDir);
      if (hit) return { type: 'internal', path: hit };
    }
    // Third-party package import (e.g. 'express', 'react')
    return { type: 'external', name: importString };
  }

  const dir = path.dirname(sourceFile);
  const resolved = path.resolve(dir, importString);
  const hit = tryResolveFileOnDisk(resolved, rootDir);
  if (hit) {
    return { type: 'internal', path: hit };
  }

  return { type: 'internal', path: path.relative(rootDir, resolved).replace(/\\/g, '/') };
}

/**
 * Standard PageRank power-iteration algorithm for graph centrality ranking.
 * High-centrality hub modules (e.g. schema, types, auth) bubble to the top.
 */
export function computePageRank(graph, damping = 0.85, iterations = 20) {
  const nodes = Array.from(graph.keys());
  const N = nodes.length;
  if (N === 0) return new Map();

  let rank = new Map();
  for (const node of nodes) {
    rank.set(node, 1 / N);
  }

  const incoming = new Map();
  const outDegree = new Map();
  for (const node of nodes) {
    incoming.set(node, []);
    outDegree.set(node, graph.get(node)?.size || 0);
  }

  for (const [node, edges] of graph.entries()) {
    for (const dep of edges) {
      if (incoming.has(dep)) {
        incoming.get(dep).push(node);
      }
    }
  }

  for (let it = 0; it < iterations; it++) {
    const nextRank = new Map();
    for (const node of nodes) {
      let sum = 0;
      for (const caller of incoming.get(node) || []) {
        const out = outDegree.get(caller) || 1;
        sum += rank.get(caller) / out;
      }
      nextRank.set(node, ((1 - damping) / N) + (damping * sum));
    }
    rank = nextRank;
  }

  return rank;
}

/**
 * Cross-File Call-Site and Usage Extractor.
 * Scans codebase to map which external files and lines call or import exported symbols.
 */

function readGoModuleName(rootDir) {
  const goModPath = path.join(rootDir, "go.mod");
  if (!fs.existsSync(goModPath)) return null;
  try {
    const raw = fs.readFileSync(goModPath, "utf-8");
    const m = raw.match(/^\s*module\s+([^\s]+)/m);
    return m ? m[1].trim() : null;
  } catch {
    return null;
  }
}

function resolvePythonImport(sourceFile, modSpec, rootDir) {
  const relDir = path.dirname(sourceFile);
  if (modSpec.startsWith(".")) {
    const dotsMatch = modSpec.match(/^(\.+)(.*)$/);
    const dots = dotsMatch ? dotsMatch[1].length : 1;
    const rest = dotsMatch ? dotsMatch[2] : "";
    let baseDir = relDir;
    for (let i = 1; i < dots; i++) baseDir = path.dirname(baseDir);
    const subPath = rest ? rest.split(".").join("/") : "";
    const candidates = subPath
      ? [path.join(baseDir, subPath + ".py"), path.join(baseDir, subPath, "__init__.py")]
      : [path.join(baseDir, "__init__.py")];
    for (const cPath of candidates) {
      if (fs.existsSync(cPath) && fs.statSync(cPath).isFile()) {
        return { type: "internal", path: path.relative(rootDir, cPath).replace(/\\/g, "/") };
      }
    }
    return { type: "external", name: modSpec };
  }
  const parts = modSpec.split(".");
  const subPath = parts.join("/");
  const candidates = [
    path.join(rootDir, subPath + ".py"),
    path.join(rootDir, subPath, "__init__.py"),
    path.join(rootDir, "src", subPath + ".py"),
    path.join(rootDir, "src", subPath, "__init__.py")
  ];
  for (const cPath of candidates) {
    if (fs.existsSync(cPath) && fs.statSync(cPath).isFile()) {
      return { type: "internal", path: path.relative(rootDir, cPath).replace(/\\/g, "/") };
    }
  }
  return { type: "external", name: parts[0] };
}

function extractPolyglotDependencies(filePath, code, rootDir, goModuleName) {
  const ext = path.extname(filePath).toLowerCase();
  const internal = [];
  const external = [];
  const symbolImports = []; // { localName, sourceFile, originalName }

  if (ext === ".py") {
    const cleaned = code
      .replace(/"""[\s\S]*?"""/g, "")
      .replace(/'''[\s\S]*?'''/g, "")
      .replace(/#.*$/gm, "");
    const collapsedPy = cleaned.replace(/from\s+(\.+[\w.]*|[\w.]+)\s+import\s*\(([\s\S]*?)\)/g, (_, mod, body) => `from ${mod} import ${body.replace(/\n/g, " ")}`);
    for (const line of collapsedPy.split("\n")) {
      const fromMatch = line.match(/^\s*from\s+(\.+[\w.]*|[\w.]+)\s+import\s+([^\n]+)/);
      if (fromMatch) {
        const modSpec = fromMatch[1].trim();
        const symsPart = fromMatch[2].replace(/[()]/g, "").trim();
        const resolved = resolvePythonImport(filePath, modSpec, rootDir);
        if (resolved.type === "internal") {
          internal.push(resolved.path);
          for (const rawSym of symsPart.split(",")) {
            const symClean = rawSym.trim();
            if (!symClean || symClean === "*") continue;
            const asParts = symClean.split(/\s+as\s+/);
            const orig = asParts[0].trim();
            const local = (asParts[1] || asParts[0]).trim();
            symbolImports.push({ localName: local, sourceFile: resolved.path, originalName: orig });
          }
        } else if (modSpec.startsWith(".")) {
          // handle "from . import foo"
          for (const rawSym of symsPart.split(",")) {
            const orig = rawSym.trim().split(/\s+as\s+/)[0].trim();
            if (!orig) continue;
            const subRes = resolvePythonImport(filePath, modSpec + orig, rootDir);
            if (subRes.type === "internal") internal.push(subRes.path);
          }
        } else {
          external.push(resolved.name);
        }
        continue;
      }
      const impMatch = line.match(/^\s*import\s+([\w.,\s]+)/);
      if (impMatch) {
        for (const item of impMatch[1].split(",")) {
          const modSpec = item.trim().split(/\s+as\s+/)[0].trim();
          if (!modSpec) continue;
          const resolved = resolvePythonImport(filePath, modSpec, rootDir);
          if (resolved.type === "internal") internal.push(resolved.path);
          else external.push(resolved.name);
        }
      }
    }
  } else if (ext === ".go") {
    const dir = path.dirname(filePath);
    const base = path.basename(filePath);
    if (base.endsWith("_test.go") && fs.existsSync(dir)) {
      for (const entry of fs.readdirSync(dir)) {
        if (entry.endsWith(".go") && !entry.endsWith("_test.go")) {
          internal.push(path.relative(rootDir, path.join(dir, entry)).replace(/\\/g, "/"));
        }
      }
    }
    const importSpecs = [];
    for (const m of code.matchAll(/^\s*import\s+(?:[\w.]+\s+)?"([^"]+)"/gm)) {
      importSpecs.push(m[1]);
    }
    for (const blk of code.matchAll(/^\s*import\s*\(([\s\S]*?)\)/gm)) {
      for (const m of blk[1].matchAll(/(?:^|\s)(?:[\w.]+\s+)?"([^"]+)"/g)) {
        importSpecs.push(m[1]);
      }
    }
    for (const imp of importSpecs) {
      if (goModuleName && (imp === goModuleName || imp.startsWith(goModuleName + "/"))) {
        const sub = imp === goModuleName ? "" : imp.slice(goModuleName.length + 1);
        const targetDir = path.join(rootDir, sub);
        if (fs.existsSync(targetDir) && fs.statSync(targetDir).isDirectory()) {
          for (const entry of fs.readdirSync(targetDir)) {
            if (entry.endsWith(".go") && !entry.endsWith("_test.go")) {
              internal.push(path.relative(rootDir, path.join(targetDir, entry)).replace(/\\/g, "/"));
            }
          }
        }
      } else {
        external.push(imp);
      }
    }
  } else if (ext === ".rs") {
    const dir = path.dirname(filePath);
    for (const m of code.matchAll(/^\s*(?:pub\s+)?mod\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*;/gm)) {
      const modName = m[1];
      for (const cand of [path.join(dir, modName + ".rs"), path.join(dir, modName, "mod.rs")]) {
        if (fs.existsSync(cand) && fs.statSync(cand).isFile()) {
          internal.push(path.relative(rootDir, cand).replace(/\\/g, "/"));
          break;
        }
      }
    }
    for (const m of code.matchAll(/^\s*(?:pub\s+)?use\s+(crate|super)::([^;]+);/gm)) {
      const anchor = m[1];
      const rawPath = m[2].split("{")[0].replace(/::\*$/, "");
      const segs = rawPath.split("::").map(s => s.trim()).filter(Boolean);
      const baseDir = anchor === "crate"
        ? (fs.existsSync(path.join(rootDir, "src")) ? path.join(rootDir, "src") : rootDir)
        : path.dirname(dir);
      // Try progressive prefixes (e.g. crate::auth::jwt::verify -> src/auth/jwt.rs or src/auth.rs)
      let matched = false;
      for (let len = segs.length; len >= 1; len--) {
        const sub = segs.slice(0, len).join("/");
        for (const cand of [path.join(baseDir, sub + ".rs"), path.join(baseDir, sub, "mod.rs")]) {
          if (fs.existsSync(cand) && fs.statSync(cand).isFile()) {
            const targetRel = path.relative(rootDir, cand).replace(/\\/g, "/");
            internal.push(targetRel);
            if (len < segs.length) {
              const sym = segs[segs.length - 1].split(/\s+as\s+/);
              const orig = sym[0]?.trim();
              const local = (sym[1] || sym[0])?.trim();
              if (orig && local && orig !== "*") {
                symbolImports.push({ localName: local, sourceFile: targetRel, originalName: orig });
              }
            }
            matched = true;
            break;
          }
        }
        if (matched) break;
      }
    }
  }

  return { internal: Array.from(new Set(internal)), external: Array.from(new Set(external)), symbolImports };
}

export function extractSymbolCallers(rootDir = process.cwd()) {
  const files = [];

  function walk(current) {
    if (!fs.existsSync(current)) return;
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const e of entries) {
      if (IGNORED.has(e.name)) continue;
      const full = path.join(current, e.name);
      if (e.isDirectory()) {
        walk(full);
      } else if (/\.(ts|tsx|js|jsx|mjs|cjs|py|go|rs)$/.test(e.name) && !e.name.endsWith('.d.ts')) {
        files.push(full);
      }
    }
  }

  walk(rootDir);

  // file -> { localImportName: { sourceFile, originalName } }
  const fileImports = new Map();
  const barrelReExports = new Map();
  const barrelWildcards = new Map();
  // sourceFile -> { symbolName: [ { file, line } ] }
  const callersMap = new Map();

  const goModuleName = readGoModuleName(rootDir);
  for (const f of files) {
    const rel = path.relative(rootDir, f).replace(/\\/g, '/');
    callersMap.set(rel, new Map());
    fileImports.set(rel, new Map());

    if (/\.(py|go|rs)$/i.test(f)) {
      try {
        const code = fs.readFileSync(f, "utf-8");
        const poly = extractPolyglotDependencies(f, code, rootDir, goModuleName);
        for (const si of poly.symbolImports) {
          fileImports.get(rel).set(si.localName, { sourceFile: si.sourceFile, originalName: si.originalName });
        }
      } catch {}
      continue;
    }

    try {
      const code = fs.readFileSync(f, 'utf-8');
      const ast = parse(code, {
        sourceType: 'module',
        plugins: ['typescript', 'jsx', 'classProperties', 'decorators-legacy', 'dynamicImport', 'exportDefaultFrom', 'exportNamespaceFrom', 'topLevelAwait']
      });

      traverse(ast, {
        ImportDeclaration(p) {
          if (!p.node.source?.value) return;
          const resolved = resolveImportPath(f, p.node.source.value, rootDir);
          if (resolved.type !== 'internal') return;

          for (const spec of p.node.specifiers || []) {
            if (spec.type === 'ImportSpecifier') {
              fileImports.get(rel).set(spec.local.name, {
                sourceFile: resolved.path,
                originalName: spec.imported.name
              });
            } else if (spec.type === 'ImportDefaultSpecifier') {
              fileImports.get(rel).set(spec.local.name, {
                sourceFile: resolved.path,
                originalName: 'default'
              });
            }
          }
        },
        ExportNamedDeclaration(p) {
          if (!p.node.source?.value) return;
          const resolved = resolveImportPath(f, p.node.source.value, rootDir);
          if (resolved.type !== 'internal') return;
          if (!barrelReExports.has(rel)) barrelReExports.set(rel, new Map());
          for (const spec of p.node.specifiers || []) {
            if (spec.type === 'ExportSpecifier') {
              const expName = spec.exported?.name || spec.exported?.value;
              const locName = spec.local?.name || spec.local?.value;
              if (expName && locName) {
                barrelReExports.get(rel).set(expName, { sourceFile: resolved.path, originalName: locName });
              }
            }
          }
        },
        ExportAllDeclaration(p) {
          if (!p.node.source?.value) return;
          const resolved = resolveImportPath(f, p.node.source.value, rootDir);
          if (resolved.type !== 'internal') return;
          if (!barrelWildcards.has(rel)) barrelWildcards.set(rel, []);
          barrelWildcards.get(rel).push(resolved.path);
        }
      });
    } catch {
      // safe fallback
    }
  }

  // Resolve barrel re-exports (export { x } from "./y" and export * from "./y") up to 3 hops
  for (const [, imports] of fileImports.entries()) {
    for (const [localName, meta] of imports.entries()) {
      let curFile = meta.sourceFile;
      let curSym = meta.originalName;
      for (let hop = 0; hop < 3; hop++) {
        const direct = barrelReExports.get(curFile)?.get(curSym);
        if (direct) {
          curFile = direct.sourceFile;
          curSym = direct.originalName;
          continue;
        }
        const wilds = barrelWildcards.get(curFile);
        if (wilds && wilds.length === 1) {
          curFile = wilds[0];
          continue;
        }
        break;
      }
      imports.set(localName, { sourceFile: curFile, originalName: curSym });
    }
  }

  // Second pass: track call sites
  for (const f of files) {
    const rel = path.relative(rootDir, f).replace(/\\/g, '/');
    const imports = fileImports.get(rel);
    if (!imports || imports.size === 0) continue;

    if (/\.(py|go|rs)$/i.test(f)) {
      try {
        const lines = fs.readFileSync(f, "utf-8").split("\n");
        for (let idx = 0; idx < lines.length; idx++) {
          const line = lines[idx];
          if (/^\s*(?:from|import)\b/.test(line)) continue;
          for (const [localName, meta] of imports.entries()) {
            const escaped = localName.replace(/[.*+?^${}()|[\]\\]/g, "\\$" + "&");
            const callRe = new RegExp("\\b" + escaped + "\\s*\\(");
            if (callRe.test(line) && callersMap.has(meta.sourceFile)) {
              const fileMap = callersMap.get(meta.sourceFile);
              if (!fileMap.has(meta.originalName)) fileMap.set(meta.originalName, []);
              const list = fileMap.get(meta.originalName);
              if (!list.some(c => c.file === rel && c.line === idx + 1)) {
                list.push({ file: rel, line: idx + 1 });
              }
            }
          }
        }
      } catch {}
      continue;
    }

    try {
      const code = fs.readFileSync(f, 'utf-8');
      const ast = parse(code, {
        sourceType: 'module',
        plugins: ['typescript', 'jsx', 'classProperties', 'decorators-legacy', 'dynamicImport', 'exportDefaultFrom', 'exportNamespaceFrom', 'topLevelAwait']
      });

      traverse(ast, {
        CallExpression(p) {
          let calleeName = null;
          if (p.node.callee.type === 'Identifier') {
            calleeName = p.node.callee.name;
          } else if (p.node.callee.type === 'MemberExpression' && p.node.callee.property.type === 'Identifier') {
            calleeName = p.node.callee.property.name;
          }

          if (calleeName && imports.has(calleeName)) {
            const { sourceFile, originalName } = imports.get(calleeName);
            if (callersMap.has(sourceFile)) {
              const fileMap = callersMap.get(sourceFile);
              if (!fileMap.has(originalName)) {
                fileMap.set(originalName, []);
              }
              const list = fileMap.get(originalName);
              const loc = p.node.loc?.start?.line || 0;
              // Avoid duplicate identical caller references
              if (!list.some(c => c.file === rel && c.line === loc)) {
                list.push({ file: rel, line: loc });
              }
            }
          }
        }
      });
    } catch {
      // safe fallback
    }
  }

  // Convert Map to plain object for easy consumption
  const result = {};
  for (const [sourceFile, symMap] of callersMap.entries()) {
    result[sourceFile] = {};
    for (const [sym, list] of symMap.entries()) {
      result[sourceFile][sym] = list;
    }
  }

  return result;
}

export function buildDependencyGraph(rootDir = process.cwd()) {
  const files = [];

  function walk(current) {
    if (!fs.existsSync(current)) return;
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const e of entries) {
      if (IGNORED.has(e.name)) continue;
      const full = path.join(current, e.name);
      if (e.isDirectory()) {
        walk(full);
      } else if (/\.(ts|tsx|js|jsx|mjs|cjs|py|go|rs)$/.test(e.name) && !e.name.endsWith('.d.ts')) {
        files.push(full);
      }
    }
  }

  walk(rootDir);

  const graph = new Map(); // file -> Set of imported files
  const externalDeps = new Set();
  const inDegree = new Map(); // file -> count of dependents

  for (const f of files) {
    const rel = path.relative(rootDir, f).replace(/\\/g, '/');
    graph.set(rel, new Set());
    inDegree.set(rel, 0);
  }

  const goModuleName = readGoModuleName(rootDir);
  for (const f of files) {
    const rel = path.relative(rootDir, f).replace(/\\/g, '/');
    if (/\.(py|go|rs)$/i.test(f)) {
      try {
        const code = fs.readFileSync(f, "utf-8");
        const poly = extractPolyglotDependencies(f, code, rootDir, goModuleName);
        for (const dep of poly.internal) graph.get(rel)?.add(dep);
        for (const ext of poly.external) externalDeps.add(ext);
      } catch {}
      continue;
    }
    try {
      const code = fs.readFileSync(f, 'utf-8');
      const ast = parse(code, {
        sourceType: 'module',
        plugins: ['typescript', 'jsx', 'classProperties', 'decorators-legacy', 'dynamicImport', 'exportDefaultFrom', 'exportNamespaceFrom', 'topLevelAwait']
      });

      traverse(ast, {
        ImportDeclaration(p) {
          if (p.node.source?.value) {
            const src = p.node.source.value;
            const resolved = resolveImportPath(f, src, rootDir);
            if (resolved.type === 'internal') {
              graph.get(rel)?.add(resolved.path);
            } else {
              externalDeps.add(resolved.name);
            }
          }
        },
        ExportNamedDeclaration(p) {
          if (p.node.source?.value) {
            const src = p.node.source.value;
            const resolved = resolveImportPath(f, src, rootDir);
            if (resolved.type === 'internal') {
              graph.get(rel)?.add(resolved.path);
            } else {
              externalDeps.add(resolved.name);
            }
          }
        },
        ExportAllDeclaration(p) {
          if (p.node.source?.value) {
            const src = p.node.source.value;
            const resolved = resolveImportPath(f, src, rootDir);
            if (resolved.type === 'internal') {
              graph.get(rel)?.add(resolved.path);
            } else {
              externalDeps.add(resolved.name);
            }
          }
        },
        ImportExpression(p) {
          if (p.node.source?.value) {
            const src = p.node.source.value;
            const resolved = resolveImportPath(f, src, rootDir);
            if (resolved.type === 'internal') {
              graph.get(rel)?.add(resolved.path);
            } else {
              externalDeps.add(resolved.name);
            }
          }
        },
        CallExpression(p) {
          const isReq = p.node.callee.name === 'require';
          const isDynImport = p.node.callee.type === 'Import';
          if ((isReq || isDynImport) && p.node.arguments[0]?.value) {
            const src = p.node.arguments[0].value;
            const resolved = resolveImportPath(f, src, rootDir);
            if (resolved.type === 'internal') {
              graph.get(rel)?.add(resolved.path);
            } else {
              externalDeps.add(resolved.name);
            }
          }
        }
      });
    } catch {
      // safe fallback on WIP files
    }
  }

  // Calculate in-degrees
  for (const [node, edges] of graph.entries()) {
    for (const dep of edges) {
      inDegree.set(dep, (inDegree.get(dep) || 0) + 1);
    }
  }

  // Calculate PageRank Centrality
  const pageRank = computePageRank(graph);

  // Detect Circular Dependencies (Cycles) using DFS
  const cycles = [];
  const visited = new Set();
  const inStack = new Set();
  const pathStack = [];

  function findCycles(node) {
    visited.add(node);
    inStack.add(node);
    pathStack.push(node);

    const edges = graph.get(node) || [];
    for (const next of edges) {
      if (!visited.has(next)) {
        findCycles(next);
      } else if (inStack.has(next)) {
        const cycleStartIndex = pathStack.indexOf(next);
        const cycle = pathStack.slice(cycleStartIndex).concat(next);
        cycles.push(cycle);
      }
    }

    pathStack.pop();
    inStack.delete(node);
  }

  for (const node of graph.keys()) {
    if (!visited.has(node)) {
      findCycles(node);
    }
  }

  return {
    modulesCount: graph.size,
    graph,
    externalDeps: Array.from(externalDeps),
    cycles,
    inDegree,
    pageRank
  };
}

export function printDependencyGraph(rootDir = process.cwd(), exportJson = false) {
  console.log(`\n${c.cyan}${c.bold}═════ AVEYX: AST CODEBASE DEPENDENCY GRAPH & PAGERANK ═════${c.reset}`);
  console.log(`Analyzing modules and import topology in: ${c.cyan}${rootDir}${c.reset}...\n`);

  const { modulesCount, graph, externalDeps, cycles, inDegree, pageRank } = buildDependencyGraph(rootDir);

  let totalEdges = 0;
  for (const edges of graph.values()) {
    totalEdges += edges.size;
  }

  console.log(`${c.bold}GRAPH TOPOLOGY SUMMARY:${c.reset}`);
  console.log(`  • Internal Modules   : ${c.green}${modulesCount}${c.reset}`);
  console.log(`  • Internal Import Links: ${c.cyan}${totalEdges}${c.reset}`);
  console.log(`  • External Packages  : ${c.magenta}${externalDeps.length}${c.reset} (${externalDeps.slice(0, 5).join(', ')}${externalDeps.length > 5 ? '...' : ''})`);
  console.log(`  • Circular Cycles    : ${cycles.length > 0 ? c.red + cycles.length + ' DETECTED' : c.green + '0 (Clean DAG)'}${c.reset}\n`);

  if (cycles.length > 0) {
    console.log(`${c.red}${c.bold}⚠️ CRITICAL: Circular Dependencies Found:${c.reset}`);
    for (let i = 0; i < cycles.length; i++) {
      console.log(`  Cycle ${i + 1}: ${c.yellow}${cycles[i].join(' -> ')}${c.reset}`);
    }
    console.log();
  }

  // Top Ranked Core Architectural Modules by PageRank Centrality
  const sortedByPageRank = Array.from(pageRank.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  if (sortedByPageRank.length > 0) {
    console.log(`${c.bold}CORE ARCHITECTURAL HUBS (PAGERANK CENTRALITY):${c.reset}`);
    for (const [mod, pr] of sortedByPageRank) {
      const dependents = inDegree.get(mod) || 0;
      console.log(`  ${c.cyan}• ${mod.padEnd(35)}${c.reset} (PageRank: ${c.green}${(pr * 100).toFixed(2)}%${c.reset}, imported by ${c.yellow}${dependents}${c.reset} files)`);
    }
    console.log();
  }

  if (exportJson) {
    const exportPath = path.join(rootDir, 'DEPENDENCY_GRAPH.json');
    const serializable = {
      modulesCount,
      totalEdges,
      externalDeps,
      cycles,
      modules: {}
    };
    for (const [k, v] of graph.entries()) {
      serializable.modules[k] = {
        imports: Array.from(v),
        dependedByCount: inDegree.get(k) || 0,
        pageRankScore: pageRank.get(k) || 0
      };
    }
    fs.writeFileSync(exportPath, JSON.stringify(serializable, null, 2));
    console.log(`  ${c.green}✓${c.reset} Exported graph topology to: ${c.cyan}${exportPath}${c.reset}\n`);
  }
}

// CLI Execution
if (process.argv[1] && process.argv[1].endsWith('dependency-graph.js')) {
  const args = process.argv.slice(2);
  const exportJson = args.includes('--json');
  const targetDir = args.find((a) => !a.startsWith('--')) || process.cwd();
  printDependencyGraph(targetDir, exportJson);
}
