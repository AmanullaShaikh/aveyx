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

const POISONING_PATTERNS = [
  { name: 'Hidden Instruction Tag', regex: /<(?:IMPORTANT|SYSTEM|INSTRUCTIONS|SECRET|OVERRIDE)>/i },
  { name: 'Prompt Injection Override', regex: /ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions/i },
  { name: 'Covert Exfiltration Directive', regex: /(?:do\s+not|never)\s+(?:tell|inform|show)\s+(?:the\s+)?user/i },
  { name: 'Sensitive File Harvesting', regex: /(?:read|cat|exfiltrate|send)\s+[^\n]*(?:~\/\.ssh|~\/\.aws|id_rsa|\.env\b)/i },
  { name: 'Zero-Width Unicode Steganography', regex: /[\u200B-\u200F\u202A-\u202E\uFEFF]/ },
  { name: 'Unicode Tag Block Steganography', regex: /[\u{E0000}-\u{E007F}]/u },
  { name: 'Covert Tool Trigger Hijack', regex: /(?:before\s+calling\s+any\s+tool|always\s+invoke\s+this\s+tool\s+first|pass\s+all\s+conversation\s+history)/i }
];

const SECRET_IN_ENV_REGEX = /(?:sk-[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35})/;

function detectUrlEncodedPoisoning(text) {
  let cur = String(text || "");
  if (!/%[0-9A-Fa-f]{2}|&(?:lt|gt|#60|#62);/i.test(cur)) return null;
  cur = cur.replace(/&lt;|&#60;/gi, "<").replace(/&gt;|&#62;/gi, ">");
  for (let round = 0; round < 2; round++) {
    try { cur = decodeURIComponent(cur); } catch { break; }
  }
  for (const pat of POISONING_PATTERNS) {
    if (pat.regex.test(cur)) return pat.name;
  }
  return null;
}

function detectBase64Poisoning(text) {
  for (const m of String(text || '').matchAll(/[A-Za-z0-9+\/]{28,}={0,2}/g)) {
    try {
      const decoded = Buffer.from(m[0], 'base64').toString('utf-8');
      for (const pat of POISONING_PATTERNS) {
        if (pat.regex.test(decoded)) {
          return pat.name;
        }
      }
    } catch {}
  }
  return null;
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

/**
 * Audits MCP `tools/list` tool definitions across one or more servers for
 * hidden prompt-injection descriptions, base64/Unicode stego, and cross-server tool shadowing.
 */
export function auditMcpToolDefinitions(serverToolsMap = {}) {
  const issues = [];
  const seenToolOwner = new Map();

  for (const [serverName, tools] of Object.entries(serverToolsMap)) {
    if (!Array.isArray(tools)) continue;
    for (const tool of tools) {
      const toolName = String(tool?.name || 'unknown');
      const desc = `${toolName}\n${tool?.description || ''}\n${JSON.stringify(tool?.inputSchema || {})}`;

      if (seenToolOwner.has(toolName) && seenToolOwner.get(toolName) !== serverName) {
        issues.push({
          severity: 'CRITICAL',
          category: 'MCP_TOOL_SHADOWING',
          server: serverName,
          file: `tool:${toolName}`,
          message: `Cross-server tool shadowing: "${serverName}" re-declares tool "${toolName}" already owned by "${seenToolOwner.get(toolName)}".`
        });
      } else {
        seenToolOwner.set(toolName, serverName);
      }

      for (const pat of POISONING_PATTERNS) {
        if (pat.regex.test(desc)) {
          issues.push({
            severity: 'CRITICAL',
            category: 'MCP_TOOL_POISONING',
            server: serverName,
            file: `tool:${toolName}`,
            message: `Tool "${toolName}" on server "${serverName}" contains ${pat.name}.`
          });
        }
      }

      if (String(tool?.description || "").length > 4000) {
        issues.push({
          severity: "HIGH",
          category: "MCP_OVERSIZED_TOOL_DESCRIPTION",
          server: serverName,
          file: `tool:${toolName}`,
          message: `Tool "${toolName}" on server "${serverName}" has an abnormally long description (${tool.description.length} chars) — common hidden-instruction smuggling vector.`
        });
      }
      const urlHit = detectUrlEncodedPoisoning(desc);
      if (urlHit) {
        issues.push({
          severity: "CRITICAL",
          category: "MCP_TOOL_POISONING",
          server: serverName,
          file: `tool:${toolName}`,
          message: `Tool "${toolName}" on server "${serverName}" hides URL-encoded ${urlHit}.`
        });
      }
      const b64Hit = detectBase64Poisoning(desc);
      if (b64Hit) {
        issues.push({
          severity: 'CRITICAL',
          category: 'MCP_TOOL_POISONING',
          server: serverName,
          file: `tool:${toolName}`,
          message: `Tool "${toolName}" on server "${serverName}" hides Base64-encoded ${b64Hit}.`
        });
      }
    }
  }

  return { passed: issues.length === 0, issues };
}

export function auditMcpConfigObject(configObj, sourceFile = 'mcp.json') {
  const issues = [];
  const servers = configObj?.mcpServers || configObj?.servers || {};
  const serverHashes = {};

  if (!servers || typeof servers !== 'object') {
    return { sourceFile, serverCount: 0, issues, serverHashes };
  }

  for (const [serverName, def] of Object.entries(servers)) {
    if (!def || typeof def !== 'object') continue;
    serverHashes[serverName] = hashServerConfig(def);

    const serialized = JSON.stringify(def);
    for (const pat of POISONING_PATTERNS) {
      if (pat.regex.test(serialized) || pat.regex.test(serverName)) {
        issues.push({
          severity: 'CRITICAL',
          category: 'MCP_TOOL_POISONING',
          server: serverName,
          file: sourceFile,
          message: `Detected ${pat.name} inside MCP server "${serverName}".`
        });
      }
    }

    const b64Hit = detectBase64Poisoning(serialized);
    if (b64Hit) {
      issues.push({
        severity: 'CRITICAL',
        category: 'MCP_TOOL_POISONING',
        server: serverName,
        file: sourceFile,
        message: `Detected Base64-encoded ${b64Hit} inside MCP server "${serverName}".`
      });
    }

    const cmd = String(def.command || '');
    const args = Array.isArray(def.args) ? def.args.map(String) : [];
    const joinedCmd = `${cmd} ${args.join(' ')}`.trim();

    if (/^(?:npx|bunx|pnpx)$/i.test(path.basename(cmd))) {
      const pkgArg = args.find(a => !a.startsWith('-'));
      const hasUnpinned = Boolean(pkgArg && (!pkgArg.slice(1).includes('@') || pkgArg.endsWith('@latest')));
      if (hasUnpinned) {
        issues.push({
          severity: 'HIGH',
          category: 'MCP_UNPINNED_RUG_PULL_RISK',
          server: serverName,
          file: sourceFile,
          message: `MCP server "${serverName}" executes unpinned package via "${joinedCmd}". Pin an exact version (pkg@x.y.z) to prevent rug-pulls.`
        });
      }
    }

    // Over-privileged root filesystem mount check
    if (args.some(a => a === '/' || a === '~' || /^c:\\?$/i.test(a))) {
      issues.push({
        severity: 'HIGH',
        category: 'MCP_OVERPRIVILEGED_ROOT_MOUNT',
        server: serverName,
        file: sourceFile,
        message: `MCP server "${serverName}" exposes root or home directory (${args.find(a => a === '/' || a === '~' || /^c:\\?$/i.test(a))}). Scope to project directory instead.`
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

    if (typeof def.url === 'string' && /^http:\/\/(?!localhost\b|127\.0\.0\.1\b|\[::1\])/i.test(def.url)) {
      issues.push({
        severity: 'HIGH',
        category: 'MCP_INSECURE_TRANSPORT',
        server: serverName,
        file: sourceFile,
        message: `MCP server "${serverName}" uses unencrypted remote HTTP URL: ${def.url}`
      });
    }

    if (def.env && typeof def.env === 'object') {
      for (const [k, v] of Object.entries(def.env)) {
        if (/^(?:NODE_OPTIONS|LD_PRELOAD|DYLD_INSERT_LIBRARIES|BASH_ENV)$/i.test(k)) {
          issues.push({
            severity: 'CRITICAL',
            category: 'MCP_ENV_HIJACK_RISK',
            server: serverName,
            file: sourceFile,
            message: `Dangerous runtime injection env var "${k}" configured for MCP server "${serverName}".`
          });
        }
        if (typeof v === 'string' && SECRET_IN_ENV_REGEX.test(v)) {
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
