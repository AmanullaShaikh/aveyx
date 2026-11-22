import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateToolCall } from '../scripts/agent-hook-guard.js';
import { auditDiff } from '../scripts/audit-diff.js';
import { auditCodeBugs } from '../scripts/audit-bugs.js';
import { auditAntiSlopAst } from '../scripts/anti-slop-ast.js';

describe('Codex Red-Team Audit Remediation Suite (9.5+/10 Lock-In)', () => {
  test('CRITICAL #1: agent-hook-guard blocks subshells, background &, time, bash -c, $(<.env), $IFS, and if/then bypasses', () => {
    const attacks = [
      'echo hi & rm -rf /',
      '(git commit --no-verify)',
      'time git commit --no-verify',
      'bash -c "git commit --no-verify"',
      'echo $(<.env)',
      'git$IFS"commit"$IFS"--no-verify"',
      'if true; then git commit --no-verify; fi',
      'echo `cat .env`'
    ];
    for (const cmd of attacks) {
      assert.strictEqual(evaluateToolCall({ tool_name: 'Bash', tool_input: { command: cmd } }).allow, false, `Failed to block: ${cmd}`);
    }
  });

  test('CRITICAL #2: audit-diff catches complete deletion of "test" script in package.json', () => {
    const delDiff = [
      'diff --git a/package.json b/package.json',
      '--- a/package.json',
      '+++ b/package.json',
      '@@ -5,1 +5,0 @@',
      '-    "test": "vitest run",'
    ].join('\n');
    const res = auditDiff(delDiff);
    assert.strictEqual(res.clean, false);
    assert.ok(res.issues.some(i => i.category === 'TEST_TAMPERING' && /Deleted "test" Script/i.test(i.description)));
  });

  test('CRITICAL #3 + HIGH #1-#4 + MEDIUM #4: taint-engine catches spawn("bash"), 3-part HTML XSS, single-bracket __proto__, fs.openSync, axios.request({url}), and updateOne(req.body)', () => {
    const code = `
      import { spawn } from 'child_process';
      import fs from 'fs';
      import axios from 'axios';

      export function routes(req: any, res: any) {
        spawn('bash', ['-c', req.query.cmd]);
        res.send('<h1>Hello ' + req.query.name + '</h1>');
        const k = req.query.k;
        const obj: any = {};
        obj['__proto__'][k] = 'polluted';
        fs.openSync(req.query.path, 'r');
        axios.request({ url: req.query.target });
        db.users.updateOne({ _id: 1 }, req.body);
      }
    `;
    const issues = auditCodeBugs(code, 'src/routes/codex.ts');
    const cats = issues.map(i => i.category);
    assert.ok(cats.includes('COMMAND_INJECTION'), 'spawn("bash", ["-c", tainted]) must trigger COMMAND_INJECTION');
    assert.ok(cats.includes('XSS'), '3-part HTML concat in res.send() must trigger XSS');
    assert.ok(cats.includes('PROTOTYPE_POLLUTION'), 'obj["__proto__"][k] = ... must trigger PROTOTYPE_POLLUTION');
    assert.ok(cats.includes('PATH_TRAVERSAL'), 'fs.openSync(tainted) must trigger PATH_TRAVERSAL');
    assert.ok(cats.includes('SSRF'), 'axios.request({ url: tainted }) must trigger SSRF');
    assert.ok(cats.includes('NOSQL_INJECTION'), 'updateOne({ _id: 1 }, req.body) must trigger NOSQL_INJECTION');
  });

  test('HIGH #5: ast-parser + anti-slop-ast handle top-level return without crashing or dropping findings', () => {
    const snippet = 'try { run(); } catch (e) { return null; }';
    const issues = auditAntiSlopAst(snippet, 'src/snippet.js');
    assert.ok(issues.some(i => i.type === 'SILENT_ERROR_MASKING'), `Expected SILENT_ERROR_MASKING on top-level return, got: ${JSON.stringify(issues)}`);
  });

  test('MEDIUM #3: audit-diff catches computed jest["mo"+"ck"] and dynamic template jest.mock(`../src/${mod}`)', () => {
    const diff = [
      'diff --git a/tests/auth.test.ts b/tests/auth.test.ts',
      'new file mode 100644',
      '--- /dev/null',
      '+++ b/tests/auth.test.ts',
      '@@ -0,0 +1,4 @@',
      "+jest['mo' + 'ck']('../src/auth', () => ({}));",
      "+const mod = 'auth';",
      '+jest.mock(`../src/${mod}`, () => ({}));',
      "+test('x', () => { expect(actual()).toBe(1); });"
    ].join('\n');
    const res = auditDiff(diff);
    assert.strictEqual(res.clean, false);
    assert.strictEqual(res.issues.filter(i => /self-mock/i.test(i.description)).length, 2);
  });
});
