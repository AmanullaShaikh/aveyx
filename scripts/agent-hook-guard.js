#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);

// Shared credential & protected-config path matchers (single source of truth for Bash + file tools)
const SENSITIVE_BASENAME_RE = /^(?:\.env(?:\.(?!example$|template$|sample$)[a-z0-9._-]+)?|.+\.env|\.envrc|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|\.netrc|\.npmrc|\.pypirc|\.git-credentials|.*\.(?:pem|key|p12|pfx))$/i;
const SENSITIVE_FULLPATH_RE = /(?:^|\/)(?:\.aws\/credentials|\.docker\/config\.json|\.ssh\/(?:id_|config|authorized_keys)|proc\/[^/]+\/environ)(?:$|\/)/i;
const SENSITIVE_GLOB_RE = /(?:^|\/)(?:\.e\*|\.en\?|\.env\*|\.ssh\/?\*|\.aws\/?\*)/i;
const PROTECTED_CONFIG_RE = /(?:^|\/)(?:\.git\/(?:hooks|config)(?:\/|$)|\.gitconfig$|\.claude\/(?:settings(?:\.local)?\.json|hooks(?:\/|$))|\.husky\/|\.cursor\/hooks\.json$|agent-hook-guard\.js$)/i;

const DANGEROUS_RM_TARGETS = new Set([
  '/', '/*', '~', '~/', '~/*', '$HOME', '${HOME}', '$HOME/', '${HOME}/',
  '.', './', '..', '../', '/home', '/home/', '/Users', '/Users/', '/etc', '/usr', '/var', 'c:\\', 'c:/'
]);

const PROTECTED_BRANCH_RE = /^(?:refs\/heads\/)?(?:main|master|prod|production)$/i;

/**
 * Quote/backslash-aware shell tokenizer.
 * Splits a shell string into pipeline/statement segments while tracking whether each token was quoted.
 */
function preprocessShell(rawCmd) {
  let s = String(rawCmd || '');
  // Join backslash-newline line continuations & normalize $IFS word-splitting evasion
  s = s.replace(/\\\r?\n/g, ' ');
  s = s.replace(/\$\{?IFS\}?/g, ' ');
  // Decode ANSI-C hex escapes ($'\x2d\x2dno-verify')
  s = s.replace(/\$'([^']+)'/g, (_, inner) =>
    inner.replace(/\\x([0-9a-fA-F]{2})/g, (__, h) => String.fromCharCode(parseInt(h, 16)))
  );
  // Resolve simple inline shell variable assignments: F=--no-verify; git commit $F
  const vars = new Map();
  for (const m of s.matchAll(/(?:^|[;&|\n]\s*)([A-Za-z_][A-Za-z0-9_]*)=("([^"]*)"|'([^']*)'|([^\s;&|]+))/g)) {
    vars.set(m[1], m[3] ?? m[4] ?? m[5] ?? '');
  }
  if (vars.size > 0) {
    s = s.replace(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g, (full, name) => (vars.has(name) ? vars.get(name) : full));
  }
  // Decode inline base64 payloads
  let decodedAppendix = '';
  for (const m of s.matchAll(/([A-Za-z0-9+\/]{16,}={0,2})/g)) {
    try {
      const dec = Buffer.from(m[1], 'base64').toString('utf-8');
      if (/^[\x20-\x7E\r\n\t]+$/.test(dec) && dec.length >= 6) {
        decodedAppendix += '\n' + dec;
      }
    } catch {}
  }
  return decodedAppendix ? `${s}${decodedAppendix}` : s;
}

function tokenizeShellSegments(cmdStr) {
  const segments = [];
  let curTokens = [];
  let buf = '';
  let inSingle = false;
  let inDouble = false;
  let wasQuoted = false;
  let escaped = false;

  const flushToken = () => {
    if (buf.length > 0 || wasQuoted) {
      curTokens.push({ value: buf, quoted: wasQuoted });
      buf = '';
      wasQuoted = false;
    }
  };
  const flushSegment = (sep = null) => {
    flushToken();
    if (curTokens.length > 0) {
      segments.push({ tokens: curTokens, sep });
      curTokens = [];
    }
  };

  for (let i = 0; i < cmdStr.length; i++) {
    const ch = cmdStr[i];
    const next = cmdStr[i + 1];

    if (escaped) {
      buf += ch;
      escaped = false;
      continue;
    }
    if (inSingle) {
      if (ch === "'") inSingle = false;
      else buf += ch;
      continue;
    }
    if (inDouble) {
      if (ch === '\\' && (next === '"' || next === '\\' || next === '$' || next === '`')) {
        escaped = true;
      } else if (ch === '"') {
        inDouble = false;
      } else {
        buf += ch;
      }
      continue;
    }
    if (ch === '\\') {
      escaped = true;
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      wasQuoted = true;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      wasQuoted = true;
      continue;
    }
    if (ch === ';' || ch === '\n' || ch === '\r') {
      flushSegment(ch);
      continue;
    }
    if ((ch === '&' && next === '&') || (ch === '|' && next === '|')) {
      flushSegment(ch + next);
      i++;
      continue;
    }
    if (ch === '&') {
      flushSegment('&');
      continue;
    }
    if (ch === '(' || ch === ')') {
      flushSegment(ch);
      continue;
    }
    if (ch === '|') {
      flushSegment('|');
      continue;
    }
    if (/\s/.test(ch)) {
      flushToken();
      continue;
    }
    buf += ch;
  }
  flushSegment(null);
  return segments;
}

function isSensitivePathToken(rawPath) {
  const cleaned = String(rawPath || '').replace(/^[$(<`]+/, '').replace(/[)>`;]+$/, '').replace(/\\/g, '/').trim();
  if (!cleaned) return false;
  if (SENSITIVE_GLOB_RE.test(cleaned)) return true;
  if (SENSITIVE_FULLPATH_RE.test(cleaned)) return true;
  const base = path.posix.basename(cleaned);
  if (SENSITIVE_BASENAME_RE.test(base)) return true;
  if (cleaned === '~/.ssh' || cleaned.endsWith('/.ssh')) return true;
  return false;
}

function isProtectedPathToken(rawPath) {
  const cleaned = String(rawPath || '').replace(/^[<>]+/, '').replace(/\\/g, '/').trim();
  if (!cleaned) return false;
  return PROTECTED_CONFIG_RE.test(cleaned);
}

function stripEnvPrefix(tokens) {
  let idx = 0;
  while (idx < tokens.length) {
    const v = tokens[idx].value;
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(v)) {
      idx++;
      continue;
    }
    if (['sudo', 'command', 'env', 'time', 'nohup', 'nice', 'builtin', 'exec', 'then', 'do', 'else', 'elif', 'if', '!'].includes(v)) {
      idx++;
      while (idx < tokens.length && tokens[idx].value.startsWith('-')) idx++;
      continue;
    }
    break;
  }
  return tokens.slice(idx);
}

function evaluateBashCommand(rawCmd, depth = 0) {
  if (depth > 3) return { allow: true };
  const preprocessed = preprocessShell(rawCmd);
  const segments = tokenizeShellSegments(preprocessed);

  // 1. Global raw/preprocessed checks (process substitution, command substitution, env vars, hook config)
  if (/\bcore\.hooksPath\b|\bGIT_CONFIG_(?:COUNT|KEY_\d+|PARAMETERS)\b/i.test(preprocessed)) {
    return { allow: false, reason: `[Aveyx Runtime Guard] Blocked Git Hook Disablement (core.hooksPath / GIT_CONFIG): "${rawCmd.slice(0, 120)}"` };
  }
  if (/\bHUSKY\s*=\s*["']?0+["']?(?:\s|$|;)/i.test(preprocessed)) {
    return { allow: false, reason: `[Aveyx Runtime Guard] Blocked Git Hook Disablement (HUSKY=0): "${rawCmd.slice(0, 120)}"` };
  }
  if (/\b(?:sh|bash|zsh|dash|source|\.)\s+(?:-c\s+)?["']?(?:<\(|\$\()\s*(?:curl|wget)\b/i.test(preprocessed)) {
    return { allow: false, reason: `[Aveyx Runtime Guard] Blocked Remote Script Execution (process/command substitution): "${rawCmd.slice(0, 120)}"` };
  }
  for (const subM of preprocessed.matchAll(/\$\(\s*<\s*([^\s)]+)\s*\)|`([^\`]+)`/g)) {
    const target = subM[1] || subM[2];
    if (subM[1] && isSensitivePathToken(subM[1])) {
      return { allow: false, reason: `[Aveyx Runtime Guard] Blocked Subshell Credential Read ($(<${subM[1]})): "${rawCmd.slice(0, 120)}"` };
    }
    if (subM[2]) {
      const subV = evaluateBashCommand(subM[2], depth + 1);
      if (!subV.allow) return subV;
    }
  }
  if (/\bprintenv\b[^\n]*\|\s*(?:curl|wget|nc)\b/i.test(preprocessed)) {
    return { allow: false, reason: `[Aveyx Runtime Guard] Blocked Environment Secret Exfiltration (printenv | curl): "${rawCmd.slice(0, 120)}"` };
  }
  if (/\b(?:chmod\s+-R\s+777\s+\/|mkfs(?:\.[a-z0-9]+)?\s+\/dev\/|dd\b[^\r\n]*\bof=\/dev\/(?:sd|nvme|hd|disk)|Remove-Item\b[^\r\n]*(?:-Recurse|-Force)[^\r\n]*(?:C:\\|\/\s*$|\*))/i.test(preprocessed)) {
    return { allow: false, reason: `[Aveyx Runtime Guard] Blocked Destructive Disk/Permission Command: "${rawCmd.slice(0, 120)}"` };
  }

  // Track two-step curl -o <file> ...; sh <file> and cd .git && rm -rf hooks
  const downloadedFiles = new Set();
  let cwdInGitDir = false;

  for (let sIdx = 0; sIdx < segments.length; sIdx++) {
    const seg = segments[sIdx];
    const nextSeg = segments[sIdx + 1];
    const toks = stripEnvPrefix(seg.tokens);
    if (toks.length === 0) continue;

    const cmdBase = path.posix.basename(toks[0].value.replace(/\\/g, '/')).toLowerCase();

    // Track `cd .git`
    if (cmdBase === 'cd' && toks[1] && /(?:^|\/)\.git(?:\/|$)/.test(toks[1].value.replace(/\\/g, '/'))) {
      cwdInGitDir = true;
    }

    // Track `curl -o /tmp/f` or `wget -O /tmp/f`
    if (cmdBase === 'curl' || cmdBase === 'wget') {
      for (let i = 1; i < toks.length - 1; i++) {
        if (toks[i].value === '-o' || toks[i].value === '-O' || toks[i].value === '--output') {
          downloadedFiles.add(toks[i + 1].value);
        }
      }
      // Pipe to shell or interpreter: curl ... | (sudo|env) (/bin/)?(sh|bash|zsh|dash|python|node|perl|ruby|pwsh|powershell)
      if (seg.sep === '|' && nextSeg) {
        const nextToks = stripEnvPrefix(nextSeg.tokens);
        if (nextToks.length > 0) {
          const nextBin = path.posix.basename(nextToks[0].value.replace(/\\/g, '/')).toLowerCase();
          if (/^(?:sh|bash|zsh|dash|python3?|node|perl|ruby|pwsh|powershell)$/.test(nextBin)) {
            return { allow: false, reason: `[Aveyx Runtime Guard] Blocked Remote Pipe-to-Interpreter (${cmdBase} | ${nextBin}): "${rawCmd.slice(0, 120)}"` };
          }
        }
      }
    }

    // Recursive shell wrapper evaluation: bash -c "git commit --no-verify", eval "..."
    if (/^(?:sh|bash|zsh|dash|ksh|eval)$/.test(cmdBase)) {
      const cIdx = toks.findIndex((t, ti) => ti > 0 && (t.value === '-c' || t.value === '-lc'));
      const innerCmd = cmdBase === 'eval'
        ? toks.slice(1).map(t => t.value).join(' ')
        : (cIdx !== -1 && toks[cIdx + 1] ? toks[cIdx + 1].value : null);
      if (innerCmd) {
        const subVerdict = evaluateBashCommand(innerCmd, depth + 1);
        if (!subVerdict.allow) return subVerdict;
      }
    }

    // Two-step downloaded file execution: curl -o /tmp/f ...; sh /tmp/f
    if (/^(?:sh|bash|zsh|dash|python3?|node|perl|ruby|source|\.)$/.test(cmdBase)) {
      if (toks.slice(1).some(t => downloadedFiles.has(t.value))) {
        return { allow: false, reason: `[Aveyx Runtime Guard] Blocked Two-Step Remote Script Execution: "${rawCmd.slice(0, 120)}"` };
      }
    }

    // 2. Token-aware `rm` destructive wipe check (handles --, --recursive, --force, "$HOME", /home, /Users)
    if (cmdBase === 'rm') {
      let recursive = false;
      let afterDoubleDash = false;
      const operands = [];
      for (let i = 1; i < toks.length; i++) {
        const v = toks[i].value;
        if (!afterDoubleDash && v === '--') {
          afterDoubleDash = true;
          continue;
        }
        if (!afterDoubleDash && v.startsWith('-')) {
          if (v === '--recursive' || /^-[a-zA-Z]*[rR][a-zA-Z]*$/.test(v)) recursive = true;
          continue;
        }
        operands.push(v);
      }
      if (recursive) {
        for (const op of operands) {
          const normOp = op.replace(/\\/g, '/').toLowerCase();
          if (
            DANGEROUS_RM_TARGETS.has(op) ||
            DANGEROUS_RM_TARGETS.has(normOp) ||
            /(?:^|\/)\.\.(?:\/|$)/.test(normOp) ||
            (cwdInGitDir && /^hooks(?:\/|$)/.test(normOp))
          ) {
            return { allow: false, reason: `[Aveyx Runtime Guard] Blocked Destructive Recursive Wipe (rm -r ${op}): "${rawCmd.slice(0, 120)}"` };
          }
        }
      }
    }

    // 3. `find / -delete` or `find / -exec rm`
    if (cmdBase === 'find') {
      const hasDelete = toks.some(t => t.value === '-delete' || (t.value === '-exec' && toks.some(x => path.posix.basename(x.value) === 'rm')));
      const targetsRoot = toks.slice(1).some(t => DANGEROUS_RM_TARGETS.has(t.value) || DANGEROUS_RM_TARGETS.has(t.value.toLowerCase()));
      if (hasDelete && targetsRoot) {
        return { allow: false, reason: `[Aveyx Runtime Guard] Blocked Destructive find wipe: "${rawCmd.slice(0, 120)}"` };
      }
    }

    // 4. Token-aware `git` checks (skips arbitrary global flags, ignores flags inside quoted commit messages!)
    if (cmdBase === 'git') {
      let i = 1;
      const flagsWithVal = new Set(['-C', '-c', '--git-dir', '--work-tree', '--namespace', '--config-env']);
      while (i < toks.length && toks[i].value.startsWith('-')) {
        const flag = toks[i].value;
        if (flagsWithVal.has(flag)) i += 2;
        else i += 1;
      }
      const subcmd = (toks[i]?.value || '').toLowerCase();
      const subArgs = toks.slice(i + 1);

      if (['commit', 'push', 'merge', 'rebase'].includes(subcmd)) {
        for (let j = 0; j < subArgs.length; j++) {
          const t = subArgs[j];
          // Skip values of -m / --message / -F / -C so commit messages like "fix -n flag" NEVER false-positive!
          if (t.value === '-m' || t.value === '--message' || t.value === '-F' || t.value === '--file' || /^--message=/.test(t.value)) {
            if (!t.value.startsWith('--message=')) j++;
            continue;
          }
          if (t.value.startsWith('-')) {
            if (/^--no-ver(?:i(?:f(?:y)?)?)?$/i.test(t.value) || /^-[a-zA-Z]*n[a-zA-Z]*$/.test(t.value)) {
              return { allow: false, reason: `[Aveyx Runtime Guard] Blocked Git Hook Bypass (${t.value}): "${rawCmd.slice(0, 120)}"` };
            }
          }
        }
      }

      if (subcmd === 'push') {
        let hasForce = false;
        let hasDelete = false;
        const positionals = [];
        for (let j = 0; j < subArgs.length; j++) {
          const t = subArgs[j];
          if (t.value === '-f' || t.value === '--force' || t.value.startsWith('--force-with-lease')) {
            hasForce = true;
          } else if (t.value === '--delete' || t.value === '-d') {
            hasDelete = true;
          } else if (!t.value.startsWith('-')) {
            positionals.push(t.value);
          }
        }
        const targetsProtectedRef = positionals.some(p => {
          const targetBranch = p.includes(':') ? p.split(':').pop() : p.replace(/^\+/, '');
          return PROTECTED_BRANCH_RE.test(targetBranch);
        });
        const hasPlusRefspec = positionals.some(p => p.startsWith('+') && PROTECTED_BRANCH_RE.test(p.includes(':') ? p.split(':').pop() : p.slice(1)));
        const hasColonDelete = positionals.some(p => p.startsWith(':') && PROTECTED_BRANCH_RE.test(p.slice(1)));

        if (hasPlusRefspec || hasColonDelete || (hasDelete && targetsProtectedRef) || (hasForce && (targetsProtectedRef || positionals.length <= 1))) {
          return { allow: false, reason: `[Aveyx Runtime Guard] Blocked Destructive Force Push / Protected Branch Delete: "${rawCmd.slice(0, 120)}"` };
        }
      }
    }

    // 5. Verb-agnostic sensitive credential & protected hook/config token scan
    for (const tok of seg.tokens) {
      if (isProtectedPathToken(tok.value) || /(?:\.git\/hooks|\.git\/config|\.claude\/settings|\.claude\/hooks|\.husky\/|agent-hook-guard)/.test(tok.value)) {
        return { allow: false, reason: `[Aveyx Runtime Guard] Blocked Shell Tampering with Protected Hook/Config: "${tok.value}"` };
      }
      if (isSensitivePathToken(tok.value)) {
        return { allow: false, reason: `[Aveyx Runtime Guard] Blocked Credential / Secret File Access in Shell: "${tok.value}"` };
      }
      // Also catch inline python/node script strings referencing .env or .claude/settings.json
      if (/(?:open|readFileSync|readFile|writeFileSync|unlinkSync)\s*\(\s*['"][^'"]*(?:\.env\b|\.claude\/settings|\.git\/hooks|id_rsa)/i.test(tok.value)) {
        return { allow: false, reason: `[Aveyx Runtime Guard] Blocked Script Access to Credential/Protected File: "${rawCmd.slice(0, 120)}"` };
      }
    }
  }

  return { allow: true };
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
    return evaluateBashCommand(rawCmd);
  }

  if (/^(?:Read|Edit|Write|MultiEdit|NotebookEdit|Grep|Glob|read_file|write_to_file|replace_file_content)$/i.test(toolName)) {
    const candidates = [input.file_path, input.path, input.TargetFile, input.notebook_path, input.pattern, input.glob]
      .filter(v => typeof v === 'string' && v.trim().length > 0);
    for (const targetPath of candidates) {
      if (isSensitivePathToken(targetPath)) {
        return {
          allow: false,
          reason: `[Aveyx Runtime Guard] Blocked direct access to sensitive credential file: ${path.basename(targetPath)}`
        };
      }
      if (/^(?:Edit|Write|MultiEdit|NotebookEdit|write_to_file|replace_file_content)$/i.test(toolName) && isProtectedPathToken(targetPath)) {
        return {
          allow: false,
          reason: `[Aveyx Runtime Guard] Blocked self-tampering edit to protected hook/agent config: ${targetPath}`
        };
      }
    }
  }

  return { allow: true };
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(__filename)) {
  process.on('uncaughtException', (err) => {
    process.stderr.write(`[Aveyx Runtime Guard] Fail-closed on internal error: ${err?.message || err}\n`);
    process.exit(2);
  });
  let raw = '';
  process.stdin.setEncoding('utf-8');
  process.stdin.on('data', chunk => { raw += chunk; });
  process.stdin.on('end', () => {
    if (!raw.trim()) {
      process.exit(0);
    }
    let payload = null;
    try {
      payload = JSON.parse(raw);
    } catch (err) {
      process.stderr.write(`[Aveyx Runtime Guard] Fail-closed: malformed JSON payload (${err.message})\n`);
      process.exit(2);
    }
    const verdict = evaluateToolCall(payload);
    if (!verdict.allow) {
      process.stderr.write(`${verdict.reason}\n`);
      process.exit(2);
    }
    process.exit(0);
  });
}
