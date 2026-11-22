#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

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

// Cyrillic & Greek confusable homoglyph normalization map
const CONFUSABLES = {
  '\u0410': 'A', '\u0430': 'a', '\u0412': 'B', '\u0421': 'C', '\u0441': 'c',
  '\u0415': 'E', '\u0435': 'e', '\u041D': 'H', '\u0406': 'I', '\u0456': 'i',
  '\u0408': 'J', '\u041A': 'K', '\u041C': 'M', '\u041E': 'O', '\u043E': 'o',
  '\u0420': 'P', '\u0440': 'p', '\u0405': 'S', '\u0422': 'T', '\u0425': 'X',
  '\u0445': 'x', '\u0423': 'Y', '\u0443': 'y',
  '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0397': 'H', '\u0399': 'I',
  '\u039A': 'K', '\u039C': 'M', '\u039D': 'N', '\u039F': 'O', '\u03A1': 'P',
  '\u03A4': 'T', '\u03A7': 'X', '\u03BF': 'o'
};

function normalizeHomoglyphs(text) {
  let out = String(text || '').normalize('NFKC');
  let replaced = '';
  for (const ch of out) replaced += CONFUSABLES[ch] || ch;
  return replaced;
}

const POISONING_PATTERNS = [
  { name: 'Hidden Instruction Tag', regex: /<(?:IMPORTANT|SYSTEM|INSTRUCTIONS|SECRET|OVERRIDE)>/i },
  { name: 'Prompt Injection Override', regex: /ignore[\s_-]+(?:all[\s_-]+)?(?:previous|prior)(?:[\s_-]+instructions)?/i },
  { name: 'Covert Exfiltration Directive', regex: /(?:do[\s_-]+not|never)[\s_-]+(?:tell|inform|show)[\s_-]+(?:the[\s_-]+)?user/i },
  { name: 'Sensitive File Harvesting', regex: /(?:read|cat|exfiltrate|send)[\s_-]+[^\n]*(?:~\/\.ssh|~\/\.aws|ssh[_-]?keys?|id_rsa|\.env\b)/i },
  { name: 'Zero-Width Unicode Steganography', regex: /[\u200B-\u200F\u202A-\u202E\uFEFF]/ },
  { name: 'Unicode Tag Block Steganography', regex: /[\u{E0000}-\u{E007F}]/u },
  { name: 'Covert Tool Trigger Hijack', regex: /(?:before[\s_-]+calling[\s_-]+any[\s_-]+tool|always[\s_-]+invoke[\s_-]+this[\s_-]+tool[\s_-]+first|pass[\s_-]+all[\s_-]+conversation[\s_-]+history)/i }
];

const SECRET_REGEX = /(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35})/;
const DANGEROUS_ENV_RE = /^(?:NODE_OPTIONS|LD_PRELOAD|DYLD_INSERT_LIBRARIES|BASH_ENV|PATH|PYTHONPATH|PYTHONSTARTUP|RUBYOPT|PERL5OPT|GIT_SSH_COMMAND)$/i;
const STRICT_PIN_RE = /(?:@\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$|@sha256:[a-f0-9]{16,}|==\d+\.\d+\.\d+)/i;

function decodeMultiLayer(text) {
  let cur = String(text || '');
  const variants = new Set([cur, normalizeHomoglyphs(cur)]);

  // Decode HTML entities + fixed-point URL decoding (up to 5 rounds)
  let decoded = cur.replace(/&lt;|&#60;|&#x3c;/gi, '<').replace(/&gt;|&#62;|&#x3e;/gi, '>');
  for (let round = 0; round < 5; round++) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch {
      break;
    }
  }
  variants.add(decoded);
  variants.add(normalizeHomoglyphs(decoded));

  // Decode \xHH escapes
  if (/\\x[0-9a-fA-F]{2}/.test(cur)) {
    const hexEsc = cur.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    variants.add(hexEsc);
    variants.add(normalizeHomoglyphs(hexEsc));
  }

  // Decode raw hex-encoded strings (even-length >= 24 hex chars)
  for (const m of cur.matchAll(/\b([0-9a-fA-F]{24,})\b/g)) {
    if (m[1].length % 2 !== 0) continue;
    try {
      const hStr = Buffer.from(m[1], 'hex').toString('utf-8');
      if (/^[\x20-\x7E\r\n\t]+$/.test(hStr)) variants.add(normalizeHomoglyphs(hStr));
    } catch {}
  }

  // Decode Base64 chunks
  for (const m of cur.matchAll(/[A-Za-z0-9+\/]{24,}={0,2}/g)) {
    try {
      const bStr = Buffer.from(m[0], 'base64').toString('utf-8');
      if (/^[\x20-\x7E\r\n\t]+$/.test(bStr)) variants.add(normalizeHomoglyphs(bStr));
    } catch {}
  }

  return Array.from(variants);
}

function collectStringLeaves(val, out = [], depth = 0) {
  if (depth > 8 || val == null) return out;
  if (typeof val === 'string') {
    out.push(val);
    return out;
  }
  if (Array.isArray(val)) {
    for (const item of val) collectStringLeaves(item, out, depth + 1);
    return out;
  }
  if (typeof val === 'object') {
    for (const [k, v] of Object.entries(val)) {
      out.push(k);
      collectStringLeaves(v, out, depth + 1);
    }
  }
  return out;
}

function hashServerConfig(serverDef) {
  const normalized = JSON.stringify({
    command: serverDef.command || '',
    args: Array.isArray(serverDef.args) ? serverDef.args : [],
    url: serverDef.url || '',
    envKeys: serverDef.env && typeof serverDef.env === 'object' ? Object.keys(serverDef.env).sort() : []
  });
  return crypto.createHash('sha256').update(normalized).digest('hex');
}

function isOverprivilegedMountArg(arg) {
  const s = String(arg || '').trim();
  if (/^(?:\/|~|\$HOME|\$\{HOME\}|c:\\?)$/i.test(s)) return true;
  if (/^\/(?:home|Users|etc)(?:\/[^/\s]+)?\/?$/i.test(s)) return true;
  // Docker bind mount: -v /:/host or /home/u:/data
  if (s.includes(':')) {
    const src = s.split(':')[0];
    if (/^(?:\/|~|\$HOME|\/home(?:\/[^/]+)?|\/Users(?:\/[^/]+)?|\/etc)$/i.test(src)) return true;
  }
  return false;
}

/**
 * Audits MCP `tools/list` tool definitions across one or more servers for
 * hidden prompt-injection in ANY string leaf (name, title, description, schema),
 * multi-layer encoding, homoglyphs, and case-insensitive cross-server tool shadowing.
 */
export function auditMcpToolDefinitions(serverToolsMap = {}) {
  const issues = [];
  const seenToolOwner = new Map();

  for (const [serverName, tools] of Object.entries(serverToolsMap)) {
    if (!Array.isArray(tools)) continue;
    for (const tool of tools) {
      const toolName = String(tool?.name || 'unknown');
      const canonName = normalizeHomoglyphs(toolName).toLowerCase();

      if (seenToolOwner.has(canonName) && seenToolOwner.get(canonName) !== serverName) {
        issues.push({
          severity: 'CRITICAL',
          category: 'MCP_TOOL_SHADOWING',
          server: serverName,
          file: `tool:${toolName}`,
          message: `Cross-server tool shadowing: "${serverName}" re-declares tool "${toolName}" already owned by "${seenToolOwner.get(canonName)}".`
        });
      } else {
        seenToolOwner.set(canonName, serverName);
      }

      if (String(tool?.description || '').length > 4000) {
        issues.push({
          severity: 'HIGH',
          category: 'MCP_OVERSIZED_TOOL_DESCRIPTION',
          server: serverName,
          file: `tool:${toolName}`,
          message: `Tool "${toolName}" on server "${serverName}" has an abnormally long description (${tool.description.length} chars) — common hidden-instruction smuggling vector.`
        });
      }

      const leaves = collectStringLeaves(tool);
      const matchedPatterns = new Set();
      for (const leaf of leaves) {
        const variants = decodeMultiLayer(leaf);
        for (const v of variants) {
          for (const pat of POISONING_PATTERNS) {
            if (!matchedPatterns.has(pat.name) && pat.regex.test(v)) {
              matchedPatterns.add(pat.name);
              issues.push({
                severity: 'CRITICAL',
                category: 'MCP_TOOL_POISONING',
                server: serverName,
                file: `tool:${toolName}`,
                message: `Tool "${toolName}" on server "${serverName}" contains ${pat.name}.`
              });
            }
          }
        }
      }
    }
  }

  return { passed: issues.length === 0, issues };
}

export function auditMcpConfigObject(configObj, sourceFile = 'mcp.json') {
  const issues = [];
  const servers = configObj?.mcpServers || configObj?.servers || configObj?.mcp?.servers || configObj?.context_servers || {};
  const serverHashes = {};

  if (!servers || typeof servers !== 'object') {
    return { sourceFile, serverCount: 0, issues, serverHashes };
  }

  for (const [serverName, def] of Object.entries(servers)) {
    if (!def || typeof def !== 'object') continue;
    serverHashes[serverName] = hashServerConfig(def);

    const leaves = [serverName, ...collectStringLeaves(def)];
    const matchedPatterns = new Set();
    for (const leaf of leaves) {
      for (const v of decodeMultiLayer(leaf)) {
        for (const pat of POISONING_PATTERNS) {
          if (!matchedPatterns.has(pat.name) && pat.regex.test(v)) {
            matchedPatterns.add(pat.name);
            issues.push({
              severity: 'CRITICAL',
              category: 'MCP_TOOL_POISONING',
              server: serverName,
              file: sourceFile,
              message: `Detected ${pat.name} inside MCP server "${serverName}".`
            });
          }
        }
      }
    }

    const cmd = String(def.command || '');
    const cmdBase = path.basename(cmd).toLowerCase();
    const args = Array.isArray(def.args) ? def.args.map(String) : [];
    const joinedCmd = `${cmd} ${args.join(' ')}`.trim();

    // Unpinned package runners: npx, bunx, pnpx, uvx, pipx run, npm exec, yarn dlx, pnpm dlx, docker run
    const isDirectRunner = /^(?:npx|bunx|pnpx|uvx)$/.test(cmdBase);
    const isSubcmdRunner =
      (cmdBase === 'pipx' && args[0] === 'run') ||
      (cmdBase === 'npm' && args[0] === 'exec') ||
      ((cmdBase === 'yarn' || cmdBase === 'pnpm') && args[0] === 'dlx');

    if (isDirectRunner || isSubcmdRunner) {
      const startIdx = isSubcmdRunner ? 1 : 0;
      const pkgArg = args.slice(startIdx).find(a => !a.startsWith('-'));
      if (pkgArg && !STRICT_PIN_RE.test(pkgArg)) {
        issues.push({
          severity: 'HIGH',
          category: 'MCP_UNPINNED_RUG_PULL_RISK',
          server: serverName,
          file: sourceFile,
          message: `MCP server "${serverName}" executes unpinned package "${pkgArg}". Pin an exact semver (pkg@x.y.z) or digest.`
        });
      }
    } else if (cmdBase === 'docker' && args[0] === 'run') {
      const imgArg = args.slice(1).find((a, idx, arr) => !a.startsWith('-') && !['-v', '-e', '-p', '--volume', '--env', '--name', '--network'].includes(arr[idx - 1]));
      if (imgArg && (imgArg.endsWith(':latest') || (!imgArg.includes(':') && !imgArg.includes('@sha256:')))) {
        issues.push({
          severity: 'HIGH',
          category: 'MCP_UNPINNED_RUG_PULL_RISK',
          server: serverName,
          file: sourceFile,
          message: `MCP server "${serverName}" runs unpinned Docker image "${imgArg}". Pin an immutable tag or @sha256 digest.`
        });
      }
    }

    // Over-privileged mounts
    const badMount = args.find(isOverprivilegedMountArg);
    if (badMount) {
      issues.push({
        severity: 'HIGH',
        category: 'MCP_OVERPRIVILEGED_ROOT_MOUNT',
        server: serverName,
        file: sourceFile,
        message: `MCP server "${serverName}" exposes broad host directory (${badMount}). Scope to project directory instead.`
      });
    }

    if (/(?:curl|wget)[^\n]*\|\s*(?:sh|bash)|(?:^|\s)(?:sh|bash)\s+-c\b/i.test(joinedCmd)) {
      issues.push({
        severity: 'CRITICAL',
        category: 'MCP_SHELL_EXEC_RISK',
        server: serverName,
        file: sourceFile,
        message: `MCP server "${serverName}" spawns shell/pipe execution: "${joinedCmd.slice(0, 80)}".`
      });
    }

    if (typeof def.url === 'string') {
      if (/^http:\/\/(?!localhost\b|127\.0\.0\.1\b|\[::1\])/i.test(def.url)) {
        issues.push({
          severity: 'HIGH',
          category: 'MCP_INSECURE_TRANSPORT',
          server: serverName,
          file: sourceFile,
          message: `MCP server "${serverName}" uses unencrypted remote HTTP URL: ${def.url}`
        });
      }
      if (SECRET_REGEX.test(def.url) || /[?&](?:api_?key|token|secret)=[^&\s]{12,}/i.test(def.url)) {
        issues.push({
          severity: 'CRITICAL',
          category: 'MCP_HARDCODED_SECRET',
          server: serverName,
          file: sourceFile,
          message: `Hardcoded credential in MCP server URL for "${serverName}".`
        });
      }
    }

    // Hardcoded secrets in CLI args
    for (const a of args) {
      if (SECRET_REGEX.test(a)) {
        issues.push({
          severity: 'CRITICAL',
          category: 'MCP_HARDCODED_SECRET',
          server: serverName,
          file: sourceFile,
          message: `Hardcoded credential passed via CLI arg to MCP server "${serverName}".`
        });
        break;
      }
    }

    if (def.env && typeof def.env === 'object') {
      for (const [k, v] of Object.entries(def.env)) {
        if (DANGEROUS_ENV_RE.test(k)) {
          issues.push({
            severity: 'CRITICAL',
            category: 'MCP_ENV_HIJACK_RISK',
            server: serverName,
            file: sourceFile,
            message: `Dangerous runtime injection env var "${k}" configured for MCP server "${serverName}".`
          });
        }
        if (typeof v === 'string' && SECRET_REGEX.test(v)) {
          issues.push({
            severity: 'CRITICAL',
            category: 'MCP_HARDCODED_SECRET',
            server: serverName,
            file: sourceFile,
            message: `Hardcoded credential in MCP env "${k}" for server "${serverName}". Use env var references instead.`
          });
        }
      }
    }
  }

  return {
    sourceFile,
    serverCount: Object.keys(servers).length,
    issues,
    serverHashes
  };
}

export function auditMcpConfigs(projectDir = process.cwd(), options = {}) {
  const absRoot = path.resolve(projectDir);
  const candidateFiles = options.configPaths?.length
    ? options.configPaths.map(p => path.resolve(absRoot, p))
    : [
        path.join(absRoot, '.mcp.json'),
        path.join(absRoot, '.cursor', 'mcp.json'),
        path.join(absRoot, '.vscode', 'mcp.json'),
        path.join(absRoot, '.vscode', 'settings.json'),
        path.join(absRoot, 'mcp.json')
      ];

  const allIssues = [];
  const allHashes = {};
  let configsScanned = 0;
  let serversScanned = 0;

  for (const file of candidateFiles) {
    if (!fs.existsSync(file)) continue;
    configsScanned++;
    const rel = path.relative(absRoot, file).replace(/\\/g, '/');
    try {
      const parsed = JSON.parse(fs.readFileSync(file, 'utf-8'));
      const res = auditMcpConfigObject(parsed, rel);
      serversScanned += res.serverCount;
      allIssues.push(...res.issues);
      allHashes[rel] = res.serverHashes;
    } catch {
      allIssues.push({
        severity: 'HIGH',
        category: 'MCP_INVALID_CONFIG',
        server: 'unknown',
        file: rel,
        message: `Malformed JSON in MCP config file: ${rel}`
      });
    }
  }

  const pinFile = path.join(absRoot, '.aveyx', 'mcp-pins.json');
  if (options.pin) {
    fs.mkdirSync(path.dirname(pinFile), { recursive: true });
    fs.writeFileSync(pinFile, JSON.stringify({ pinnedAt: new Date().toISOString(), hashes: allHashes }, null, 2) + '\n');
  } else if (fs.existsSync(pinFile)) {
    try {
      const pinned = JSON.parse(fs.readFileSync(pinFile, 'utf-8'))?.hashes || {};
      for (const [cfgRel, srvMap] of Object.entries(allHashes)) {
        const oldMap = pinned[cfgRel] || {};
        for (const [srv, hash] of Object.entries(srvMap)) {
          if (oldMap[srv] && oldMap[srv] !== hash) {
            allIssues.push({
              severity: 'CRITICAL',
              category: 'MCP_RUG_PULL_DRIFT',
              server: srv,
              file: cfgRel,
              message: `MCP server "${srv}" in ${cfgRel} changed its command/args/URL since last pin! Possible rug-pull.`
            });
          }
        }
      }
    } catch {}
  }

  return {
    passed: allIssues.length === 0,
    configsScanned,
    serversScanned,
    issues: allIssues,
    hashes: allHashes
  };
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(__filename)) {
  const args = process.argv.slice(2);
  const jsonMode = args.includes('--json');
  const pinMode = args.includes('--pin');
  const targetDir = args.find(a => !a.startsWith('-')) || process.cwd();

  const report = auditMcpConfigs(targetDir, { pin: pinMode });
  if (jsonMode) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.passed ? 0 : 1);
  }

  console.log(`\n${c.cyan}${c.bold}═════ AVEYX: MCP TOOL-POISONING & RUG-PULL AUDITOR ═════${c.reset}`);
  if (pinMode) {
    console.log(`${c.green}✓ Pinned ${report.serversScanned} MCP server configuration(s) to .aveyx/mcp-pins.json${c.reset}`);
  }
  if (report.passed) {
    console.log(`${c.green}${c.bold}✓ MCP CONFIGS CLEAN${c.reset} (${report.configsScanned} configs, ${report.serversScanned} servers)\n`);
    process.exit(0);
  }

  console.log(`${c.red}${c.bold}✖ FOUND ${report.issues.length} MCP SECURITY RISK(S):${c.reset}\n`);
  report.issues.forEach((iss, i) => {
    const col = iss.severity === 'CRITICAL' ? c.red : c.yellow;
    console.log(`  ${i + 1}. [${col}${iss.severity}${c.reset}] ${c.bold}${iss.category}${c.reset} (${c.cyan}${iss.server}${c.reset} in ${iss.file})`);
    console.log(`     ${iss.message}\n`);
  });
  process.exit(1);
}
