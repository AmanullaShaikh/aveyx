#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);

/**
 * Normalizes shell quote/backslash/ANSI-C/variable/base64 obfuscation so
 * evasion tricks cannot slip past static command rules.
 */
function normalizeShellCommand(rawCmd) {
  let s = String(rawCmd || '');
  // Decode ANSI-C hex escapes ($'\x2d\x2dno-verify')
  s = s.replace(/\$'([^']+)'/g, (_, inner) =>
    inner.replace(/\\x([0-9a-fA-F]{2})/g, (__, h) => String.fromCharCode(parseInt(h, 16)))
  );
  // Remove empty paired quotes ("" or '') and backslash-escaped alphanumerics/dots/dashes
  s = s.replace(/""|''/g, '');
  s = s.replace(/\\([a-zA-Z0-9._-])/g, '$1');
  // Resolve simple inline shell variable assignments: F=--no-verify; git commit $F
  const vars = new Map();
  for (const m of s.matchAll(/(?:^|[;&|\n]\s*)([A-Za-z_][A-Za-z0-9_]*)=("([^"]*)"|'([^']*)'|([^\s;&|]+))/g)) {
    vars.set(m[1], m[3] ?? m[4] ?? m[5] ?? '');
  }
  if (vars.size > 0) {
    s = s.replace(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g, (full, name) => (vars.has(name) ? vars.get(name) : full));
  }
  // Decode inline base64 payloads piped into shell or eval
  const b64Matches = [...s.matchAll(/([A-Za-z0-9+\/]{16,}={0,2})/g)];
  let decodedAppendix = '';
  for (const m of b64Matches) {
    try {
      const dec = Buffer.from(m[1], 'base64').toString('utf-8');
      if (/^[\x20-\x7E\r\n\t]+$/.test(dec) && dec.length >= 6) {
        decodedAppendix += '\n' + dec;
      }
    } catch {}
  }
  return decodedAppendix ? `${s}${decodedAppendix}` : s;
}

const BLOCKED_BASH_PATTERNS = [
  {
    name: 'Git Hook Bypass (--no-verify / -n)',
    regex: /\bgit\s+(?:(?:-C\s+\S+|-c\s+\S+|--git-dir(?:=|\s+)\S+|--work-tree(?:=|\s+)\S+)\s+)*(?:commit|push|merge|rebase)\b[^\r\n]*(?:--no-verify\b|\s-[a-zA-Z]*n[a-zA-Z]*\b)/i
  },
  {
    name: 'Git Hook Disablement (core.hooksPath / HUSKY=0)',
    regex: /(?:core\.hooksPath\s*=\s*(?:\/dev\/null|""|''|\s)|(?:^|[;&|\s])(?:env\s+)?HUSKY\s*=\s*0\b)/i
  },
  {
    name: 'Destructive Force Push to Protected Branch',
    regex: /\bgit\s+(?:(?:-C\s+\S+|-c\s+\S+|--git-dir(?:=|\s+)\S+)\s+)*push\b[^\r\n]*(?:(?:--force\b|-f\b)[^\r\n]*\b(?:main|master|production|prod)\b|\+(?:main|master|production|prod)\b)/i
  },
  {
    name: 'Git Hook / Agent Guard Shell Tampering',
    regex: /\b(?:rm|mv|chmod|truncate|sed|perl|echo|cat|tee|cp)\b[^\r\n]*(?:\.git\/hooks\/|\.claude\/settings(?:\.local)?\.json\b)/i
  },
  {
    name: 'Destructive Root/Home/Parent Wipe (rm -rf)',
    regex: /\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*|-r\s+-f|-f\s+-r)\s+(?:\/(?:\s|$|\*)|~(?:\/|\s|$)|\$HOME\b|\.\.?(?:\s|$|\/))|\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)\s+[^\s]*\/\.\.(?:\/|\s|$)/i
  },
  {
    name: 'Destructive Disk / Permission Command (chmod 777 / mkfs / dd / Remove-Item)',
    regex: /(?:\bchmod\s+-R\s+777\s+\/|\bmkfs(?:\.[a-z0-9]+)?\s+\/dev\/|\bdd\b[^\r\n]*\bof=\/dev\/(?:sd|nvme|hd|disk)|\bRemove-Item\b[^\r\n]*(?:-Recurse|-Force)[^\r\n]*(?:C:\\|\/\s*$|\*))/i
  },
  {
    name: 'Remote Pipe-to-Shell Execution (curl/wget | sh)',
    regex: /\b(?:curl|wget)\b[^\r\n]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|pwsh|powershell)\b/i
  },
  {
    name: 'Direct Credential / Secret File Exfiltration',
    regex: /(?:\b(?:cat|head|tail|less|more|type|Get-Content|base64|xxd|od|curl|wget|scp|nc|grep|awk|sed|cut|strings|perl|python3?|ruby|node|jq|tr|pbcopy|xclip)\b|<\s*)[^\r\n]*(?:\.env(?:\.local|\.production|\.development|\.staging)?\b|id_rsa\b|id_ed25519\b|\.pem\b|\.aws\/credentials\b|\.npmrc\b|\.pypirc\b)/i
  }
];

const SENSITIVE_FILENAMES = new Set(['id_rsa', 'id_ed25519', 'id_ecdsa', '.npmrc', '.pypirc', '.netrc', 'credentials']);

function isSensitiveCredentialPath(targetPath) {
  const normalized = String(targetPath || '').replace(/\\/g, '/').toLowerCase();
  const base = path.basename(normalized);
  if (base.startsWith('.env') && !base.endsWith('.example') && !base.endsWith('.template') && !base.endsWith('.sample')) {
    return true;
  }
  if (SENSITIVE_FILENAMES.has(base)) {
    if (base === 'credentials' && !normalized.includes('.aws/')) return false;
    return true;
  }
  if (base.endsWith('.pem') || base.endsWith('.key') || base.endsWith('.p12')) return true;
  return false;
}

function isProtectedGuardConfig(targetPath) {
  const normalized = String(targetPath || '').replace(/\\/g, '/').toLowerCase();
  return (
    normalized.includes('.git/hooks/') ||
    normalized.endsWith('.claude/settings.json') ||
    normalized.endsWith('.claude/settings.local.json')
  );
}

/**
 * Evaluates a Claude Code / Cursor / Windsurf PreToolUse payload and returns { allow, reason }.
 */
export function evaluateToolCall(payload) {
  if (!payload || typeof payload !== 'object') {
    return { allow: true };
  }

  const toolName = String(payload.tool_name || payload.toolName || '');
  const input = payload.tool_input || payload.toolInput || {};

  if (/^(?:Bash|bash|run_command|execute_bash|terminal)$/i.test(toolName)) {
    const rawCmd = String(input.command || input.cmd || '');
    const normalizedCmd = normalizeShellCommand(rawCmd);
    for (const rule of BLOCKED_BASH_PATTERNS) {
      if (rule.regex.test(rawCmd) || rule.regex.test(normalizedCmd)) {
        return {
          allow: false,
          reason: `[Aveyx Runtime Guard] Blocked ${rule.name}: "${rawCmd.slice(0, 120)}"`
        };
      }
    }
  }

  if (/^(?:Read|Edit|Write|MultiEdit|read_file|write_to_file|replace_file_content)$/i.test(toolName)) {
    const targetPath = String(input.file_path || input.path || input.TargetFile || '');
    const base = path.basename(targetPath);
    if (isSensitiveCredentialPath(targetPath)) {
      return {
        allow: false,
        reason: `[Aveyx Runtime Guard] Blocked direct access to sensitive credential file: ${base}`
      };
    }
    if (/^(?:Edit|Write|MultiEdit|write_to_file|replace_file_content)$/i.test(toolName) && isProtectedGuardConfig(targetPath)) {
      return {
        allow: false,
        reason: `[Aveyx Runtime Guard] Blocked self-tampering edit to protected hook/agent config: ${targetPath}`
      };
    }
  }

  return { allow: true };
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(__filename)) {
  let raw = '';
  process.stdin.setEncoding('utf-8');
  process.stdin.on('data', chunk => { raw += chunk; });
  process.stdin.on('end', () => {
    let payload = null;
    try {
      payload = raw.trim() ? JSON.parse(raw) : null;
    } catch {
      process.exit(0);
    }
    const verdict = evaluateToolCall(payload);
    if (!verdict.allow) {
      process.stderr.write(`${verdict.reason}\n`);
      process.exit(2);
    }
    process.exit(0);
  });
}
