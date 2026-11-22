import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';

const traverse = _traverse.default || _traverse;

const SANITIZER_CALLEES = new Set([
  'parseInt', 'Number', 'parseFloat', 'BigInt', 'Boolean',
  'encodeURIComponent', 'encodeURI', 'escapeHtml', 'escape', 'basename'
]);

const SANITIZER_MEMBERS = new Set([
  'path.basename', 'DOMPurify.sanitize', 'validator.escape', 'validator.toInt',
  'validator.isUUID', 'he.encode', 'xss'
]);

const TAINT_SOURCE_ROOTS = new Set(['req', 'request', 'ctx']);
const TAINT_SOURCE_PROPS = new Set(['body', 'query', 'params', 'headers', 'cookies']);

function getMemberChain(node) {
  const parts = [];
  let cur = node;
  while (cur) {
    if (cur.type === 'Identifier') {
      parts.unshift(cur.name);
      break;
    }
    if (cur.type === 'MemberExpression') {
      const prop = cur.property?.name || cur.property?.value;
      if (!prop) return null;
      parts.unshift(String(prop));
      cur = cur.object;
    } else {
      return null;
    }
  }
  return parts;
}

export function isSanitizerCall(node) {
  if (!node || node.type !== 'CallExpression') return false;
  if (node.callee.type === 'Identifier' && SANITIZER_CALLEES.has(node.callee.name)) {
    return true;
  }
  if (node.callee.type === 'MemberExpression') {
    const chain = getMemberChain(node.callee);
    if (chain) {
      const joined = chain.join('.');
      if (SANITIZER_MEMBERS.has(joined)) return true;
      const last = chain[chain.length - 1];
      if (last === 'basename' && chain[0] === 'path') return true;
      if (last === 'sanitize' || last === 'safeParse') return true;
      if (last === 'parse' && /(?:schema|zod|validator|z)$/i.test(chain[chain.length - 2] || '')) return true;
    }
    if (node.callee.property?.name === 'parse' && node.callee.object?.type === 'CallExpression') {
      const innerChain = getMemberChain(node.callee.object.callee);
      if (innerChain && (innerChain[0] === 'z' || innerChain[0] === 'zod' || innerChain[0] === 'yup')) return true;
    }
  }
  return false;
}

export function isDirectTaintSource(node) {
  if (!node) return false;
  if (node.type === 'MemberExpression') {
    const chain = getMemberChain(node);
    if (!chain || chain.length < 2) return false;
    if (TAINT_SOURCE_ROOTS.has(chain[0]) && TAINT_SOURCE_PROPS.has(chain[1])) return true;
    if (chain[0] === 'ctx' && chain[1] === 'request' && TAINT_SOURCE_PROPS.has(chain[2])) return true;
    if (chain[0] === 'process' && chain[1] === 'argv') return true;
    // Browser DOM taint sources
    if (chain[0] === 'location' && ['hash', 'search', 'href', 'pathname'].includes(chain[1])) return true;
    if (chain[0] === 'window' && chain[1] === 'location' && ['hash', 'search', 'href'].includes(chain[2])) return true;
    if (chain[0] === 'window' && chain[1] === 'name') return true;
    if (chain[0] === 'document' && (chain[1] === 'cookie' || chain[1] === 'URL' || chain[1] === 'referrer')) return true;
    if ((chain[0] === 'event' || chain[0] === 'e') && chain[1] === 'data') return true;
  }
  if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
    const chain = getMemberChain(node.callee);
    if (chain && chain[chain.length - 1] === 'get' && /searchParams/i.test(chain.join('.'))) {
      return true;
    }
  }
  return false;
}

function getFnNodeFromPath(p) {
  if (p.isFunctionDeclaration()) return { name: p.node.id?.name, fn: p.node };
  if (p.isVariableDeclarator() && p.node.id?.type === 'Identifier') {
    const init = p.node.init;
    if (init && (init.type === 'ArrowFunctionExpression' || init.type === 'FunctionExpression')) {
      return { name: p.node.id.name, fn: init };
    }
  }
  return null;
}

function exprUsesParamOrSource(node, paramIndexMap, fnMap, visited = new Set(), scope = null) {
  if (!node) return { fromSource: false, fromParams: new Set(), hasSqlConcat: false };
  if (node.type === 'AwaitExpression') return exprUsesParamOrSource(node.argument, paramIndexMap, fnMap, visited, scope);
  if (isSanitizerCall(node)) return { fromSource: false, fromParams: new Set(), hasSqlConcat: false };
  if (isDirectTaintSource(node)) return { fromSource: true, fromParams: new Set(), hasSqlConcat: false };

  if (node.type === 'Identifier') {
    if (paramIndexMap.has(node.name)) {
      return { fromSource: false, fromParams: new Set([paramIndexMap.get(node.name)]), hasSqlConcat: false };
    }
    if (visited.has(node.name)) return { fromSource: false, fromParams: new Set(), hasSqlConcat: false };
    visited.add(node.name);
    const binding = scope?.getBinding(node.name);
    if (binding?.path?.node?.init) {
      return exprUsesParamOrSource(binding.path.node.init, paramIndexMap, fnMap, visited, binding.scope);
    }
    return { fromSource: false, fromParams: new Set(), hasSqlConcat: false };
  }

  if (node.type === 'MemberExpression') {
    const rootChain = getMemberChain(node);
    if (rootChain && paramIndexMap.has(rootChain[0])) {
      return { fromSource: false, fromParams: new Set([paramIndexMap.get(rootChain[0])]), hasSqlConcat: false };
    }
    return exprUsesParamOrSource(node.object, paramIndexMap, fnMap, visited, scope);
  }

  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const l = exprUsesParamOrSource(node.left, paramIndexMap, fnMap, visited, scope);
    const r = exprUsesParamOrSource(node.right, paramIndexMap, fnMap, visited, scope);
    const strHint = (node.left.type === 'StringLiteral' && /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b/i.test(node.left.value)) ||
      (node.right.type === 'StringLiteral' && /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b/i.test(node.right.value));
    return {
      fromSource: l.fromSource || r.fromSource,
      fromParams: new Set([...l.fromParams, ...r.fromParams]),
      hasSqlConcat: l.hasSqlConcat || r.hasSqlConcat || (strHint && (l.fromParams.size > 0 || r.fromParams.size > 0 || l.fromSource || r.fromSource))
    };
  }

  if (node.type === 'TemplateLiteral') {
    let fromSource = false;
    const fromParams = new Set();
    let hasSqlConcat = false;
    const rawText = node.quasis.map(q => q.value.raw).join(' ');
    const sqlHint = /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b/i.test(rawText);
    for (const ex of node.expressions || []) {
      const sub = exprUsesParamOrSource(ex, paramIndexMap, fnMap, visited, scope);
      if (sub.fromSource) fromSource = true;
      for (const idx of sub.fromParams) fromParams.add(idx);
      if (sub.hasSqlConcat || (sqlHint && (sub.fromSource || sub.fromParams.size > 0))) hasSqlConcat = true;
    }
    return { fromSource, fromParams, hasSqlConcat };
  }

  if (node.type === 'ConditionalExpression') {
    const c = exprUsesParamOrSource(node.consequent, paramIndexMap, fnMap, visited, scope);
    const a = exprUsesParamOrSource(node.alternate, paramIndexMap, fnMap, visited, scope);
    return {
      fromSource: c.fromSource || a.fromSource,
      fromParams: new Set([...c.fromParams, ...a.fromParams]),
      hasSqlConcat: c.hasSqlConcat || a.hasSqlConcat
    };
  }

  if (node.type === 'CallExpression' && node.callee.type === 'Identifier') {
    const calleeSum = fnMap.get(node.callee.name);
    if (calleeSum) {
      let fromSource = calleeSum.returnsSource;
      const fromParams = new Set();
      let hasSqlConcat = calleeSum.returnsSqlConcat;
      for (const idx of calleeSum.paramToReturn) {
        if (node.arguments[idx]) {
          const argRes = exprUsesParamOrSource(node.arguments[idx], paramIndexMap, fnMap, visited, scope);
          if (argRes.fromSource) fromSource = true;
          for (const pIdx of argRes.fromParams) fromParams.add(pIdx);
          if (argRes.hasSqlConcat) hasSqlConcat = true;
        }
      }
      return { fromSource, fromParams, hasSqlConcat };
    }
  }

  return { fromSource: false, fromParams: new Set(), hasSqlConcat: false };
}

export function summarizeFunctionTaints(ast) {
  const summaries = new Map();
  if (!ast) return summaries;

  const fnEntries = [];
  try {
    traverse(ast, {
      FunctionDeclaration(p) {
        const info = getFnNodeFromPath(p);
        if (info?.name) fnEntries.push({ ...info, scope: p.scope });
      },
      VariableDeclarator(p) {
        const info = getFnNodeFromPath(p);
        if (info?.name) fnEntries.push({ ...info, scope: p.scope });
      }
    });
  } catch {
    return summaries;
  }

  for (let pass = 0; pass < 2; pass++) {
    for (const { name, fn, scope } of fnEntries) {
      const paramIndexMap = new Map();
      (fn.params || []).forEach((param, idx) => {
        if (param.type === 'Identifier') paramIndexMap.set(param.name, idx);
        else if (param.type === 'AssignmentPattern' && param.left?.type === 'Identifier') {
          paramIndexMap.set(param.left.name, idx);
        }
      });

      const paramToReturn = new Set();
      let returnsSource = false;
      let returnsSqlConcat = false;

      if (fn.body?.type === 'BlockStatement') {
        for (const stmt of fn.body.body) {
          if (stmt.type === 'ReturnStatement' && stmt.argument) {
            const res = exprUsesParamOrSource(stmt.argument, paramIndexMap, summaries, new Set(), scope);
            if (res.fromSource) returnsSource = true;
            if (res.hasSqlConcat) returnsSqlConcat = true;
            for (const idx of res.fromParams) paramToReturn.add(idx);
          }
        }
      } else if (fn.body) {
        const res = exprUsesParamOrSource(fn.body, paramIndexMap, summaries, new Set(), scope);
        if (res.fromSource) returnsSource = true;
        if (res.hasSqlConcat) returnsSqlConcat = true;
        for (const idx of res.fromParams) paramToReturn.add(idx);
      }

      summaries.set(name, { paramToReturn, returnsSource, returnsSqlConcat });
    }
  }

  return summaries;
}

export function extractFileExportSummaries(code) {
  try {
    const ast = parse(code, {
      sourceType: 'module',
      plugins: ['typescript', 'jsx', 'classProperties', 'decorators-legacy', 'dynamicImport', 'exportDefaultFrom', 'exportNamespaceFrom', 'topLevelAwait', 'asyncGenerators']
    });
    return summarizeFunctionTaints(ast);
  } catch {
    return new Map();
  }
}

function isNestedDestructuredFromTaint(binding) {
  if (!binding?.path?.isVariableDeclarator()) return false;
  const init = binding.path.node.init;
  if (!init) return false;
  if (isDirectTaintSource(init)) return true;
  if (init.type === 'Identifier' && TAINT_SOURCE_ROOTS.has(init.name) && binding.path.node.id?.type === 'ObjectPattern') {
    for (const prop of binding.path.node.id.properties || []) {
      const k = prop.key?.name || prop.key?.value;
      if (TAINT_SOURCE_PROPS.has(k)) return true;
    }
  }
  return false;
}

/**
 * Evaluates source -> sanitizer -> sink taint flows across intra-file and imported helpers.
 */
export function analyzeInterProceduralTaint(ast, filePath, importedFnSummaries = new Map()) {
  const issues = [];
  if (!ast) return issues;

  const isTestFile = /\.(test|spec)\.[a-z]+$/i.test(filePath) || /(?:^|\/)tests\//i.test(filePath);
  const namedFsFns = new Set();
  const execAliases = new Set(['exec', 'execSync', 'execa', 'execaSync']);
  const spawnAliases = new Set(['spawn', 'spawnSync', 'execFile', 'execFileSync']);

  try {
    traverse(ast, {
      ImportDeclaration(p) {
        const src = p.node.source?.value || '';
        if (src === 'fs' || src === 'node:fs' || src === 'fs/promises' || src === 'node:fs/promises') {
          for (const spec of p.node.specifiers || []) {
            if (spec.type === 'ImportSpecifier') {
              const orig = spec.imported?.name || spec.imported?.value;
              if (['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'createReadStream'].includes(orig)) {
                namedFsFns.add(spec.local.name);
              }
            }
          }
        }
        if (src === 'child_process' || src === 'node:child_process' || src === 'execa') {
          for (const spec of p.node.specifiers || []) {
            if (spec.type === 'ImportSpecifier') {
              const orig = spec.imported?.name || spec.imported?.value;
              if (['exec', 'execSync', 'execa', 'execaSync'].includes(orig)) execAliases.add(spec.local.name);
              if (['spawn', 'spawnSync', 'execFile', 'execFileSync'].includes(orig)) spawnAliases.add(spec.local.name);
            }
          }
        }
      },
      VariableDeclarator(p) {
        // Handle renamed destructuring: const { execSync: e } = cp; const { readFileSync: rf } = fs;
        if (p.node.id?.type === 'ObjectPattern') {
          for (const prop of p.node.id.properties || []) {
            if (prop.type !== 'ObjectProperty') continue;
            const orig = prop.key?.name || prop.key?.value;
            const local = prop.value?.type === 'Identifier' ? prop.value.name : orig;
            if (!orig || !local) continue;
            if (['exec', 'execSync', 'execa', 'execaSync'].includes(orig)) execAliases.add(local);
            if (['spawn', 'spawnSync', 'execFile', 'execFileSync'].includes(orig)) spawnAliases.add(local);
            if (['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'createReadStream'].includes(orig)) namedFsFns.add(local);
          }
        }
      }
    });
  } catch {}

  const localSummaries = summarizeFunctionTaints(ast);
  const allSummaries = new Map([...importedFnSummaries.entries(), ...localSummaries.entries()]);

  function isExprTainted(node, scope, visited = new Set()) {
    if (!node) return { tainted: false, sqlConcat: false };
    if (node.type === 'AwaitExpression') return isExprTainted(node.argument, scope, visited);
    if (node.type === 'SpreadElement') return isExprTainted(node.argument, scope, visited);
    if (isSanitizerCall(node)) return { tainted: false, sqlConcat: false };
    if (isDirectTaintSource(node)) return { tainted: true, sqlConcat: false };

    if (node.type === 'BinaryExpression' && node.operator === '+') {
      const l = isExprTainted(node.left, scope, visited);
      const r = isExprTainted(node.right, scope, visited);
      const hasSqlHint = (node.left.type === 'StringLiteral' && /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b/i.test(node.left.value)) ||
        (node.right.type === 'StringLiteral' && /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b/i.test(node.right.value));
      return { tainted: l.tainted || r.tainted, sqlConcat: l.sqlConcat || r.sqlConcat || (hasSqlHint && (l.tainted || r.tainted)) };
    }

    if (node.type === 'TemplateLiteral') {
      let tainted = false;
      let sqlConcat = false;
      const rawText = node.quasis.map(q => q.value.raw).join(' ');
      const hasSqlHint = /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b/i.test(rawText);
      for (const ex of node.expressions || []) {
        const sub = isExprTainted(ex, scope, visited);
        if (sub.tainted) tainted = true;
        if (sub.sqlConcat || (hasSqlHint && sub.tainted)) sqlConcat = true;
      }
      return { tainted, sqlConcat };
    }

    if (node.type === 'ArrayExpression') {
      let tainted = false;
      let sqlConcat = false;
      for (const el of node.elements || []) {
        const sub = isExprTainted(el, scope, visited);
        if (sub.tainted) tainted = true;
        if (sub.sqlConcat) sqlConcat = true;
      }
      return { tainted, sqlConcat };
    }

    if (node.type === 'ObjectExpression') {
      for (const prop of node.properties || []) {
        if (prop.type === 'SpreadElement') {
          const sub = isExprTainted(prop.argument, scope, visited);
          if (sub.tainted) return sub;
        }
      }
      return { tainted: false, sqlConcat: false };
    }

    if (node.type === 'ConditionalExpression') {
      const c = isExprTainted(node.consequent, scope, visited);
      const a = isExprTainted(node.alternate, scope, visited);
      return { tainted: c.tainted || a.tainted, sqlConcat: c.sqlConcat || a.sqlConcat };
    }

    if (node.type === 'Identifier') {
      if (visited.has(node.name)) return { tainted: false, sqlConcat: false };
      visited.add(node.name);
      const binding = scope?.getBinding(node.name);
      if (!binding) return { tainted: false, sqlConcat: false };

      if (isNestedDestructuredFromTaint(binding)) {
        return { tainted: true, sqlConcat: false };
      }
      if (binding.path?.node?.init) {
        const initRes = isExprTainted(binding.path.node.init, binding.scope, visited);
        if (initRes.tainted) return initRes;
      }
      for (const cv of binding.constantViolations || []) {
        if (cv.isAssignmentExpression() && (cv.node.operator === '=' || cv.node.operator === '+=')) {
          const cvRes = isExprTainted(cv.node.right, cv.scope, visited);
          if (cvRes.tainted) return cvRes;
        }
      }
      return { tainted: false, sqlConcat: false };
    }

    if (node.type === 'NewExpression' && node.callee?.type === 'Identifier' && node.callee.name === 'URL' && node.arguments?.[0]) {
      return isExprTainted(node.arguments[0], scope, visited);
    }

    if (node.type === 'MemberExpression') {
      return isExprTainted(node.object, scope, visited);
    }

    if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
      const mChain = getMemberChain(node.callee);
      const prop = node.callee.property?.name;
      if (mChain && mChain[0] === 'path' && (mChain[1] === 'join' || mChain[1] === 'resolve')) {
        for (const arg of node.arguments || []) {
          const argRes = isExprTainted(arg, scope, visited);
          if (argRes.tainted) return argRes;
        }
      }
      // String method propagation: str.replace('X', tainted), str.concat(tainted), str.slice(), str.trim(), str.padStart(), str.repeat()
      if (['replace', 'replaceAll', 'concat', 'slice', 'substring', 'trim', 'toLowerCase', 'toUpperCase', 'padStart', 'padEnd', 'repeat'].includes(prop)) {
        const objRes = isExprTainted(node.callee.object, scope, visited);
        if (objRes.tainted) return objRes;
        for (const arg of node.arguments || []) {
          const argRes = isExprTainted(arg, scope, visited);
          if (argRes.tainted) {
            const sqlHint = node.callee.object?.type === 'StringLiteral' && /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b/i.test(node.callee.object.value);
            return { tainted: true, sqlConcat: argRes.sqlConcat || sqlHint };
          }
        }
      }
    }

    if (node.type === 'CallExpression' && node.callee.type === 'Identifier') {
      const sum = allSummaries.get(node.callee.name);
      if (sum) {
        if (sum.returnsSource) return { tainted: true, sqlConcat: sum.returnsSqlConcat };
        for (const idx of sum.paramToReturn) {
          if (node.arguments[idx]) {
            const argRes = isExprTainted(node.arguments[idx], scope, visited);
            if (argRes.tainted) return { tainted: true, sqlConcat: sum.returnsSqlConcat || argRes.sqlConcat };
          }
        }
      }
    }

    return { tainted: false, sqlConcat: false };
  }

  try {
    traverse(ast, {
      JSXAttribute(p) {
        if (p.node.name?.name === 'dangerouslySetInnerHTML' && p.node.value?.type === 'JSXExpressionContainer') {
          const expr = p.node.value.expression;
          if (expr?.type === 'ObjectExpression') {
            for (const prop of expr.properties || []) {
              if ((prop.key?.name || prop.key?.value) === '__html' && isExprTainted(prop.value, p.scope).tainted) {
                issues.push({
                  file: filePath,
                  line: p.node.loc?.start?.line || 1,
                  severity: 'HIGH',
                  category: 'XSS',
                  type: 'XSS',
                  message: 'Unsanitized tainted value passed to dangerouslySetInnerHTML.__html (React XSS).'
                });
              }
            }
          }
        }
      },

      CallExpression(p) {
        const line = p.node.loc?.start?.line || 1;
        const callee = p.node.callee;
        const propName = callee.type === 'MemberExpression' ? (callee.property?.name || callee.property?.value) : null;
        const objName = callee.type === 'MemberExpression' ? callee.object?.name : null;
        const memberChain = callee.type === 'MemberExpression' ? getMemberChain(callee) : null;
        const fnName = callee.type === 'Identifier' ? callee.name : null;

        // 1. Command Injection: exec, execSync, execa, execaSync, shelljs.exec, renamed destructured aliases
        if (
          !isTestFile &&
          ((fnName && execAliases.has(fnName)) ||
           ['exec', 'execSync', 'execa', 'execaSync'].includes(propName))
        ) {
          const argsToCheck = (fnName === 'execa' || fnName === 'execaSync' || propName === 'execa' || propName === 'execaSync')
            ? p.node.arguments
            : [p.node.arguments[0]];
          if (argsToCheck.some(a => a && a.type !== 'StringLiteral' && isExprTainted(a, p.scope).tainted)) {
            issues.push({
              file: filePath,
              line,
              severity: 'CRITICAL',
              category: 'COMMAND_INJECTION',
              type: 'COMMAND_INJECTION',
              message: 'Inter-procedural taint flow: unsanitized user input reaches shell/command execution.'
            });
          }
        }

        // 2. Path Traversal: fs.*, fs.promises.*, named ESM fs imports, res.sendFile, res.download
        const isFsPromises = memberChain && memberChain[0] === 'fs' && memberChain[1] === 'promises' &&
          ['readFile', 'writeFile', 'appendFile', 'unlink', 'open'].includes(memberChain[2]);
        if (
          !isTestFile &&
          ((objName === 'fs' && ['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'createReadStream'].includes(propName)) ||
           isFsPromises ||
           (fnName && namedFsFns.has(fnName)) ||
           ((propName === 'sendFile' || propName === 'download') && ['res', 'reply'].includes(objName)))
        ) {
          const arg0 = p.node.arguments[0];
          if (arg0 && isExprTainted(arg0, p.scope).tainted) {
            issues.push({
              file: filePath,
              line,
              severity: 'CRITICAL',
              category: 'PATH_TRAVERSAL',
              type: 'PATH_TRAVERSAL',
              message: `Inter-procedural taint flow: unsanitized user input reaches filesystem/download sink.`
            });
          }
        }

        // 3. SSRF: fetch, got, ky, needle, axios.*, axios({ url }), http(s).get/request
        const isHttpClientCall =
          ['fetch', 'got', 'ky', 'needle'].includes(fnName) ||
          (['axios', 'http', 'https', 'got', 'ky'].includes(objName) && ['get', 'post', 'put', 'delete', 'request'].includes(propName));
        if (!isTestFile && isHttpClientCall) {
          const arg0 = p.node.arguments[0];
          if (arg0 && isExprTainted(arg0, p.scope).tainted) {
            issues.push({
              file: filePath,
              line,
              severity: 'HIGH',
              category: 'SSRF',
              type: 'SSRF',
              message: 'Inter-procedural taint flow: unsanitized user input controls outbound request URL (SSRF risk).'
            });
          }
        }
        if (!isTestFile && (fnName === 'axios' || fnName === 'got') && p.node.arguments[0]?.type === 'ObjectExpression') {
          for (const prop of p.node.arguments[0].properties || []) {
            const k = prop.key?.name || prop.key?.value;
            if ((k === 'url' || k === 'baseURL') && isExprTainted(prop.value, p.scope).tainted) {
              issues.push({
                file: filePath,
                line,
                severity: 'HIGH',
                category: 'SSRF',
                type: 'SSRF',
                message: `Inter-procedural taint flow: unsanitized user input controls ${fnName}({ ${k} }) (SSRF risk).`
              });
            }
          }
        }

        // 4. Inter-procedural SQLi (including spread args `db.query(...a)` and `.replace` tainted SQL)
        if (propName && ['query', 'raw', '$queryRawUnsafe', '$executeRawUnsafe', 'execute'].includes(propName)) {
          const arg0 = p.node.arguments[0];
          if (arg0) {
            const res = isExprTainted(arg0, p.scope);
            if (res.tainted && (res.sqlConcat || arg0.type === 'SpreadElement' || (arg0.type === 'CallExpression' && arg0.callee?.property?.name === 'replace'))) {
              issues.push({
                file: filePath,
                line,
                severity: 'CRITICAL',
                category: 'SQL_INJECTION',
                type: 'SQL_INJECTION',
                message: 'Inter-procedural taint flow: unsanitized user input flows into dynamic SQL query. Use parameterized queries.'
              });
            }
          }
        }

        // 5. NoSQL Injection: direct req.body, aliased filter, $where, AND ObjectExpression property value tainted ({ u: req.body.u })
        if (!isTestFile && propName && ['find', 'findOne', 'findOneAndUpdate', 'deleteMany', 'updateMany'].includes(propName)) {
          const arg0 = p.node.arguments[0];
          if (arg0 && (isDirectTaintSource(arg0) || (arg0.type === 'Identifier' && isExprTainted(arg0, p.scope).tainted))) {
            issues.push({
              file: filePath,
              line,
              severity: 'HIGH',
              category: 'NOSQL_INJECTION',
              type: 'NOSQL_INJECTION',
              message: `Unsanitized request object passed directly into .${propName}() (NoSQL operator injection risk).`
            });
          } else if (arg0?.type === 'ObjectExpression') {
            for (const prop of arg0.properties || []) {
              const k = prop.key?.name || prop.key?.value;
              if (k === '$where' && isExprTainted(prop.value, p.scope).tainted) {
                issues.push({
                  file: filePath,
                  line,
                  severity: 'CRITICAL',
                  category: 'NOSQL_INJECTION',
                  type: 'NOSQL_INJECTION',
                  message: 'Unsanitized user input passed into MongoDB $where operator (NoSQL code injection).'
                });
              } else if (prop.type === 'ObjectProperty' && isExprTainted(prop.value, p.scope).tainted) {
                issues.push({
                  file: filePath,
                  line,
                  severity: 'HIGH',
                  category: 'NOSQL_INJECTION',
                  type: 'NOSQL_INJECTION',
                  message: `Unsanitized user input passed as query filter value for "${k}" in .${propName}() (NoSQL operator injection risk if attacker sends {$ne: null}). Cast with String() or validate with Zod.`
                });
                break;
              }
            }
          }
        }

        // 6. Prototype Pollution: Object.assign, _.merge, _.defaultsDeep, _.mergeWith (direct, aliased, or spread object)
        const isMergeSink = (objName === 'Object' && propName === 'assign') || (['_', 'lodash'].includes(objName) && ['merge', 'defaultsDeep', 'mergeWith'].includes(propName));
        if (!isTestFile && isMergeSink && p.node.arguments.length >= 2) {
          const srcArg = p.node.arguments.slice(1).find(a => isDirectTaintSource(a) || (a && isExprTainted(a, p.scope).tainted));
          if (srcArg) {
            issues.push({
              file: filePath,
              line,
              severity: 'HIGH',
              category: 'PROTOTYPE_POLLUTION',
              type: 'PROTOTYPE_POLLUTION',
              message: `Unsanitized request object merged via ${objName}.${propName}() (Prototype Pollution / Mass Assignment risk).`
            });
          }
        }

        // 7. Code Injection & DOM XSS
        const isIndirectEval = callee?.type === 'SequenceExpression' && callee.expressions?.some(e => e.type === 'Identifier' && e.name === 'eval');
        const isGlobalEval = propName === 'eval' && ['globalThis', 'global', 'window'].includes(objName);
        const isFnConstructorCall = callee?.type === 'MemberExpression' && (callee.property?.name === 'constructor' || callee.property?.value === 'constructor');
        const isTimerCodeExec = (fnName === 'setTimeout' || fnName === 'setInterval') && p.node.arguments[0] && isExprTainted(p.node.arguments[0], p.scope).tainted;

        if (!isTestFile && objName === 'document' && (propName === 'write' || propName === 'writeln')) {
          if (p.node.arguments[0] && isExprTainted(p.node.arguments[0], p.scope).tainted) {
            issues.push({ file: filePath, line, severity: 'HIGH', category: 'XSS', type: 'XSS', message: 'Unsanitized user input passed to document.write() (DOM XSS).' });
          }
        }
        if (!isTestFile && propName === 'insertAdjacentHTML' && p.node.arguments[1] && isExprTainted(p.node.arguments[1], p.scope).tainted) {
          issues.push({ file: filePath, line, severity: 'HIGH', category: 'XSS', type: 'XSS', message: 'Unsanitized user input passed to insertAdjacentHTML() (DOM XSS).' });
        }
        if (!isTestFile && (fnName === 'eval' || isIndirectEval || isGlobalEval || isFnConstructorCall || isTimerCodeExec || (objName === 'vm' && /^runIn/.test(propName || '')))) {
          const arg0 = p.node.arguments[0];
          if (arg0 && isExprTainted(arg0, p.scope).tainted) {
            issues.push({
              file: filePath,
              line,
              severity: 'CRITICAL',
              category: 'CODE_INJECTION',
              type: 'CODE_INJECTION',
              message: 'Inter-procedural taint flow: unsanitized user input reaches dynamic code execution sink (Arbitrary Code Execution).'
            });
          }
        }

        // 8. Spawn / execFile with tainted executable OR tainted args array when { shell: true }
        if (!isTestFile && ((fnName && spawnAliases.has(fnName)) || spawnAliases.has(propName))) {
          const arg0 = p.node.arguments[0];
          const arg1 = p.node.arguments[1];
          const hasShellTrue = p.node.arguments.some(a =>
            a?.type === 'ObjectExpression' &&
            a.properties?.some(pr => (pr.key?.name || pr.key?.value) === 'shell' && pr.value?.type === 'BooleanLiteral' && pr.value.value === true)
          );
          if ((arg0 && arg0.type !== 'StringLiteral' && isExprTainted(arg0, p.scope).tainted) || (hasShellTrue && arg1 && isExprTainted(arg1, p.scope).tainted)) {
            issues.push({
              file: filePath,
              line,
              severity: 'CRITICAL',
              category: 'COMMAND_INJECTION',
              type: 'COMMAND_INJECTION',
              message: 'Inter-procedural taint flow: unsanitized user input reaches spawn/execFile executable or shell:true arguments.'
            });
          }
        }

        // 8b. Reflected HTML XSS in res.send / res.end
        if (!isTestFile && (propName === 'send' || propName === 'end') && ['res', 'reply'].includes(objName)) {
          const arg0 = p.node.arguments[0];
          const hasHtmlTag =
            (arg0?.type === 'TemplateLiteral' && /<[a-z][^>]*>/i.test(arg0.quasis.map(q => q.value.raw).join(''))) ||
            (arg0?.type === 'BinaryExpression' && arg0.operator === '+' &&
              ((arg0.left?.type === 'StringLiteral' && /<[a-z][^>]*>/i.test(arg0.left.value)) ||
               (arg0.right?.type === 'StringLiteral' && /<[a-z][^>]*>/i.test(arg0.right.value))));
          if (hasHtmlTag && isExprTainted(arg0, p.scope).tainted) {
            issues.push({
              file: filePath,
              line,
              severity: 'HIGH',
              category: 'XSS',
              type: 'XSS',
              message: 'Inter-procedural taint flow: unsanitized user input interpolated into HTML response in res.send() (Reflected XSS).'
            });
          }
        }

        // 9. Open Redirect: res.redirect, res.writeHead(302, { Location }), res.setHeader('Location', ...)
        if (!isTestFile && propName === 'redirect' && ['res', 'reply'].includes(objName)) {
          const targetArg = p.node.arguments.length >= 2 ? p.node.arguments[1] : p.node.arguments[0];
          if (targetArg && isExprTainted(targetArg, p.scope).tainted) {
            issues.push({ file: filePath, line, severity: 'HIGH', category: 'OPEN_REDIRECT', type: 'OPEN_REDIRECT', message: 'Unsanitized user input controls redirect target (Open Redirect risk).' });
          }
        }
        if (!isTestFile && propName === 'setHeader' && ['res', 'reply'].includes(objName)) {
          const hName = p.node.arguments[0]?.value;
          if (typeof hName === 'string' && hName.toLowerCase() === 'location' && isExprTainted(p.node.arguments[1], p.scope).tainted) {
            issues.push({ file: filePath, line, severity: 'HIGH', category: 'OPEN_REDIRECT', type: 'OPEN_REDIRECT', message: 'Unsanitized user input controls Location redirect header (Open Redirect risk).' });
          }
        }
        if (!isTestFile && propName === 'writeHead' && ['res', 'reply'].includes(objName)) {
          const hdrObj = p.node.arguments.find(a => a?.type === 'ObjectExpression');
          if (hdrObj) {
            for (const prop of hdrObj.properties || []) {
              const k = String(prop.key?.name || prop.key?.value || '').toLowerCase();
              if (k === 'location' && isExprTainted(prop.value, p.scope).tainted) {
                issues.push({ file: filePath, line, severity: 'HIGH', category: 'OPEN_REDIRECT', type: 'OPEN_REDIRECT', message: 'Unsanitized user input controls writeHead Location header (Open Redirect risk).' });
              }
            }
          }
        }
      },

      NewExpression(p) {
        const isFunctionCtor = p.node.callee?.type === 'Identifier' && p.node.callee.name === 'Function';
        const isVmScript = p.node.callee?.type === 'MemberExpression' && p.node.callee.object?.name === 'vm' && p.node.callee.property?.name === 'Script';
        if (!isTestFile && (isFunctionCtor || isVmScript)) {
          if ((p.node.arguments || []).some(a => isExprTainted(a, p.scope).tainted)) {
            issues.push({
              file: filePath,
              line: p.node.loc?.start?.line || 1,
              severity: 'CRITICAL',
              category: 'CODE_INJECTION',
              type: 'CODE_INJECTION',
              message: `Inter-procedural taint flow: unsanitized user input passed to new ${isVmScript ? 'vm.Script' : 'Function'}() (Arbitrary Code Execution).`
            });
          }
        }
      },

      AssignmentExpression(p) {
        if (
          !isTestFile &&
          p.node.left?.type === 'MemberExpression' &&
          p.node.left.computed &&
          p.node.left.object?.type === 'MemberExpression' &&
          p.node.left.object.computed &&
          isExprTainted(p.node.left.object.property, p.scope).tainted &&
          isExprTainted(p.node.left.property, p.scope).tainted
        ) {
          issues.push({
            file: filePath,
            line: p.node.loc?.start?.line || 1,
            severity: 'CRITICAL',
            category: 'PROTOTYPE_POLLUTION',
            type: 'PROTOTYPE_POLLUTION',
            message: 'Nested dynamic bracket assignment using unsanitized user keys (Prototype Pollution risk).'
          });
        }
        if (p.node.left?.type === 'MemberExpression' && (p.node.left.property?.name === 'innerHTML' || p.node.left.property?.name === 'outerHTML')) {
          if (isExprTainted(p.node.right, p.scope).tainted) {
            issues.push({
              file: filePath,
              line: p.node.loc?.start?.line || 1,
              severity: 'HIGH',
              category: 'XSS',
              type: 'XSS',
              message: `Inter-procedural taint flow: unsanitized user input assigned to ${p.node.left.property.name} (XSS risk).`
            });
          }
        }
      }
    });
  } catch {
    // safe fallback
  }

  return issues;
}
