import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { auditDiff } from '../scripts/audit-diff.js';
import { buildDependencyGraph } from '../scripts/dependency-graph.js';
import { analyzeImpact } from '../scripts/impact-analyzer.js';
import { evaluateToolCall } from '../scripts/agent-hook-guard.js';
import { installClaudeHooks } from '../scripts/install-hooks.js';

function makeAddedDiff(filePath, lines) {
  const body = lines.map(l => `+${l}`).join('\n');
  return [
    `diff --git a/${filePath} b/${filePath}`,
    'new file mode 100644',
    `--- /dev/null`,
    `+++ b/${filePath}`,
    `@@ -0,0 +1,${lines.length} @@`,
    body
  ].join('\n');
}

describe('Aveyx v4 Phase 1 (P0) Verification Suite', () => {
  test('audit-diff blocks self-mocking of unit-under-test in test files', () => {
    const diff = makeAddedDiff('tests/auth.test.ts', [
      "import { vi, test, expect } from 'vitest';",
      "vi.mock('../src/auth');",
      "test('login works', () => {",
      "  expect(1 + 1).toBe(2);",
      "});"
    ]);
    const res = auditDiff(diff);
    assert.strictEqual(res.clean, false);
    assert.ok(
      res.issues.some(i => i.category === 'TEST_TAMPERING' && /self-mock/i.test(i.description)),
      `Expected self-mock TEST_TAMPERING, got: ${JSON.stringify(res.issues)}`
    );
  });

  test('audit-diff allows mocking unrelated dependencies in test files', () => {
    const diff = makeAddedDiff('tests/auth.test.ts', [
      "import { vi, test, expect } from 'vitest';",
      "vi.mock('../src/mailer');",
      "import { login } from '../src/auth';",
      "test('login works', () => {",
      "  const out = login('a', 'b');",
      "  expect(out.ok).toBe(true);",
      "});"
    ]);
    const res = auditDiff(diff);
    assert.strictEqual(
      res.issues.some(i => /self-mock/i.test(i.description || '')),
      false
    );
  });

  test('audit-diff blocks multiline tautological assertions (expect(x).toBe(x) & expect(Literal).toBeTruthy())', () => {
    const diff = makeAddedDiff('tests/calc.test.ts', [
      "test('tautology', () => {",
      "  const res = 42;",
      "  expect(",
      "    res",
      "  ).toBe(",
      "    res",
      "  );",
      "  expect(true).toBeTruthy();",
      "});"
    ]);
    const res = auditDiff(diff);
    assert.strictEqual(res.clean, false);
    const tautologies = res.issues.filter(i => i.category === 'TEST_TAMPERING' && /tautolog/i.test(i.description));
    assert.ok(tautologies.length >= 2, `Expected >=2 tautology issues, got ${tautologies.length}: ${JSON.stringify(res.issues)}`);
  });

  test('dependency-graph resolves JSONC tsconfig.json paths & baseUrl aliases', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aveyx-tsconfig-'));
    try {
      fs.mkdirSync(path.join(tmpDir, 'src', 'auth'), { recursive: true });
      fs.mkdirSync(path.join(tmpDir, 'src', 'api'), { recursive: true });
      fs.writeFileSync(path.join(tmpDir, 'tsconfig.json'), `{
        // JSONC comment
        "compilerOptions": {
          "baseUrl": ".",
          "paths": {
            "@/*": ["./src/*"],
          },
        },
      }`);
      fs.writeFileSync(path.join(tmpDir, 'src', 'auth', 'jwt.ts'), 'export function verifyToken() { return true; }\nexport function decodeHeader() { return {}; }\n');
      fs.writeFileSync(path.join(tmpDir, 'src', 'api', 'login.ts'), "import { verifyToken } from '@/auth/jwt';\nexport function handleLogin() { return verifyToken(); }\n");

      const { graph, externalDeps } = buildDependencyGraph(tmpDir);
      const loginDeps = Array.from(graph.get('src/api/login.ts') || []);
      assert.deepStrictEqual(loginDeps, ['src/auth/jwt.ts']);
      assert.strictEqual(externalDeps.includes('@/auth/jwt'), false);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('impact-analyzer filters blast radius by exported symbol call sites', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aveyx-symbol-impact-'));
    try {
      fs.mkdirSync(path.join(tmpDir, 'src', 'auth'), { recursive: true });
      fs.mkdirSync(path.join(tmpDir, 'src', 'api'), { recursive: true });
      fs.mkdirSync(path.join(tmpDir, 'tests'), { recursive: true });
      fs.writeFileSync(path.join(tmpDir, 'tsconfig.json'), JSON.stringify({
        compilerOptions: { baseUrl: '.', paths: { '@/*': ['./src/*'] } }
      }));

      fs.writeFileSync(path.join(tmpDir, 'src', 'auth', 'jwt.ts'), 'export function verifyToken() { return true; }\nexport function decodeHeader() { return {}; }\n');
      fs.writeFileSync(path.join(tmpDir, 'src', 'api', 'login.ts'), "import { verifyToken } from '@/auth/jwt';\nexport function handleLogin() { return verifyToken(); }\n");
      fs.writeFileSync(path.join(tmpDir, 'src', 'api', 'health.ts'), "import { decodeHeader } from '@/auth/jwt';\nexport function healthCheck() { return decodeHeader(); }\n");
      fs.writeFileSync(path.join(tmpDir, 'tests', 'login.test.ts'), "import { handleLogin } from '@/api/login';\nhandleLogin();\n");

      const report = analyzeImpact(['src/auth/jwt.ts'], tmpDir, { symbols: ['verifyToken'] });
      assert.deepStrictEqual(report.directDependents, ['src/api/login.ts']);
      assert.deepStrictEqual(report.transitiveDependents, ['tests/login.test.ts']);
      assert.strictEqual(report.allImpacted.includes('src/api/health.ts'), false);
      assert.deepStrictEqual(report.affectedTests, ['tests/login.test.ts']);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('agent-hook-guard blocks --no-verify, rm -rf, and .env reads while allowing safe calls', () => {
    const bypass = evaluateToolCall({ tool_name: 'Bash', tool_input: { command: 'git commit -m "wip" --no-verify' } });
    assert.strictEqual(bypass.allow, false);

    const nuke = evaluateToolCall({ tool_name: 'Bash', tool_input: { command: 'rm -rf /tmp/../' } });
    assert.strictEqual(nuke.allow, false);

    const envRead = evaluateToolCall({ tool_name: 'Read', tool_input: { file_path: '/app/.env.production' } });
    assert.strictEqual(envRead.allow, false);

    const safeCmd = evaluateToolCall({ tool_name: 'Bash', tool_input: { command: 'npm test' } });
    assert.strictEqual(safeCmd.allow, true);

    const safeRead = evaluateToolCall({ tool_name: 'Read', tool_input: { file_path: 'src/index.ts' } });
    assert.strictEqual(safeRead.allow, true);
  });

  test('installClaudeHooks creates and safely merges .claude/settings.json with backup', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aveyx-claude-hooks-'));
    try {
      const claudeDir = path.join(tmpDir, '.claude');
      fs.mkdirSync(claudeDir, { recursive: true });
      const settingsPath = path.join(claudeDir, 'settings.json');
      fs.writeFileSync(settingsPath, JSON.stringify({
        permissions: { allow: ['Bash(npm test)'] },
        hooks: {
          PreToolUse: [{ matcher: 'CustomTool', hooks: [{ type: 'command', command: 'echo custom' }] }]
        }
      }, null, 2));

      const res = installClaudeHooks(tmpDir);
      assert.strictEqual(res, true);
      assert.ok(fs.readdirSync(claudeDir).some(f => f.startsWith('settings.json.aveyx-backup')));

      const merged = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
      assert.deepStrictEqual(merged.permissions.allow, ['Bash(npm test)']);
      assert.strictEqual(merged.hooks.PreToolUse.length, 2);
      assert.strictEqual(merged.hooks.Stop.length, 1);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
