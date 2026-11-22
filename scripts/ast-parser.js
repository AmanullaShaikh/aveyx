import { parse as babelParse } from '@babel/parser';

let oxcModule = null;
let oxcChecked = false;
let oxcVersion = null;

/**
 * Attempts to dynamically load optional `oxc-parser` fast-path if installed by the user.
 * Never throws when absent — falls back cleanly to @babel/parser.
 */
export async function initFastParser() {
  if (oxcChecked) {
    return { available: Boolean(oxcModule), backend: oxcModule ? 'oxc' : 'babel', version: oxcVersion };
  }
  oxcChecked = true;
  try {
    const mod = await import('oxc-parser');
    if (mod && (typeof mod.parseSync === 'function' || typeof mod.parse === 'function')) {
      oxcModule = mod;
      oxcVersion = mod.version || 'installed';
    }
  } catch {
    oxcModule = null;
  }
  return { available: Boolean(oxcModule), backend: oxcModule ? 'oxc' : 'babel', version: oxcVersion };
}

export function getParserBackendInfo() {
  return {
    active: oxcModule ? 'oxc+babel' : 'babel',
    oxcAvailable: Boolean(oxcModule),
    oxcVersion
  };
}

export const DEFAULT_BABEL_PLUGINS = [
  'typescript',
  'jsx',
  'classProperties',
  'decorators-legacy',
  'dynamicImport',
  'exportDefaultFrom',
  'exportNamespaceFrom',
  'topLevelAwait',
  'asyncGenerators'
];

export function parseBabelAst(code, extraOptions = {}) {
  return babelParse(code, {
    sourceType: 'module',
    plugins: DEFAULT_BABEL_PLUGINS,
    ...extraOptions
  });
}

/**
 * Unified parser entry point supporting optional oxc-parser fast-path for syntax/import extraction.
 * Returns { backend, ast, errors, imports, exports }.
 */
export function parseSourceFast(code, filePath = 'input.ts', options = {}) {
  const preferOxc = options.backend !== 'babel' && Boolean(oxcModule);
  if (preferOxc) {
    try {
      const fn = oxcModule.parseSync || oxcModule.parse;
      const res = fn(filePath, code, { sourceType: 'module' });
      if (res && (!res.errors || res.errors.length === 0)) {
        const imports = (res.module?.staticImports || []).map(i => i.moduleRequest?.value).filter(Boolean);
        const exports = (res.module?.staticExports || []).flatMap(e => (e.entries || []).map(en => en.exportName?.name)).filter(Boolean);
        return { backend: 'oxc', ast: res.program, errors: [], imports, exports };
      }
    } catch {
      // Fall through to Babel
    }
  }

  const ast = parseBabelAst(code, options.babelOptions);
  const imports = [];
  const exports = [];
  for (const node of ast.program?.body || []) {
    if (node.type === 'ImportDeclaration' && node.source?.value) {
      imports.push(node.source.value);
    } else if (node.type === 'ExportNamedDeclaration') {
      if (node.source?.value) imports.push(node.source.value);
      if (node.declaration?.id?.name) exports.push(node.declaration.id.name);
      if (node.declaration?.declarations) {
        for (const d of node.declaration.declarations) {
          if (d.id?.name) exports.push(d.id.name);
        }
      }
      for (const s of node.specifiers || []) {
        if (s.exported?.name) exports.push(s.exported.name);
      }
    } else if (node.type === 'ExportAllDeclaration' && node.source?.value) {
      imports.push(node.source.value);
    } else if (node.type === 'ExportDefaultDeclaration') {
      exports.push('default');
    }
  }
  return { backend: 'babel', ast, errors: [], imports, exports };
}
