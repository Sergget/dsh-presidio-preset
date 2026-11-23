// Integration test for the unified DSH bundle `plugins/dsh-presidio-pii/`.
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const BUNDLE_DIR = join(REPO, 'plugins', 'dsh-presidio-pii');

let passes = 0;
let failures = 0;
function check(label, cond, detail) {
  if (cond) {
    passes += 1;
    console.log(`PASS ${label}`);
  } else {
    failures += 1;
    console.log(`FAIL ${label}${detail ? ` :: ${detail}` : ''}`);
  }
}

// 1. package.json & exports
const pkg = JSON.parse(readFileSync(join(BUNDLE_DIR, 'package.json'), 'utf8'));
check('bundle name is dsh-presidio-pii', pkg.name === 'dsh-presidio-pii', pkg.name);
check('bundle patch points to ./cordis.patch.yml', pkg.dsh?.bundle?.patch === './cordis.patch.yml');
const requiredExports = ['.', './terms', './guard', './fs', './client', './icon', './locale/*.json', './package.json'];
for (const key of requiredExports) {
  check(`export ${key} declared`, Boolean(pkg.exports?.[key]));
}

const bundleRequire = createRequire(join(BUNDLE_DIR, 'package.json'));
for (const sub of ['dsh-presidio-pii', 'dsh-presidio-pii/terms', 'dsh-presidio-pii/guard', 'dsh-presidio-pii/fs', 'dsh-presidio-pii/package.json']) {
  let ok = false;
  try {
    bundleRequire.resolve(sub);
    ok = true;
  } catch {}
  check(`subpath resolves: ${sub}`, ok);
}

// 2. client.js MODULE_ID matches package name
const clientSrc = readFileSync(join(BUNDLE_DIR, 'client.js'), 'utf8');
check('client MODULE_ID matches package.json name', clientSrc.includes("const MODULE_ID = 'dsh-presidio-pii'"));

// 2b. 路径解析必须只有一份实现：guard.js 从 ./paths.mjs 引入，不得再内联副本。
const guardSrc = readFileSync(join(BUNDLE_DIR, 'lib', 'guard.js'), 'utf8');
check("guard.js imports resolveDataPaths from './paths.mjs'",
  /import\s*\{[^}]*resolveDataPaths[^}]*\}\s*from\s*["']\.\/paths\.mjs["']/.test(guardSrc));
check("guard.js imports ensureDefaultPreset from './paths.mjs'",
  /import\s*\{[^}]*ensureDefaultPreset[^}]*\}\s*from\s*["']\.\/paths\.mjs["']/.test(guardSrc));
check('guard.js does not re-inline resolveDataPaths', !/\bfunction\s+resolveDataPaths\s*\(/.test(guardSrc));
check('guard.js does not re-inline ensureDefaultPreset', !/\bfunction\s+ensureDefaultPreset\s*\(/.test(guardSrc));
check('guard.js reuses shared ReDoS guard', /from\s*["']\.\/regex-safety\.mjs["']/.test(guardSrc)
  && guardSrc.includes('hasNestedQuantifier('));

// 3. cordis.patch.yml has zero hardcoded paths / placeholders
const patchRaw = readFileSync(join(BUNDLE_DIR, 'cordis.patch.yml'), 'utf8');
// 拼装绝对路径样本，避免本文件自身被 check_paths 之类的扫描器按字面量命中。
const absSamples = [
  ['E:', '\\', 'Code'].join(''),
  ['E:', '/', 'Code'].join(''),
  ['C:', '\\', 'Users'].join(''),
];
const placeholderSamples = ['__' + 'REPO' + '__', '__' + 'DSH_HOME' + '__'];
const hardcoded = [...placeholderSamples, ...absSamples].filter((s) => patchRaw.toLowerCase().includes(s.toLowerCase()));
check('cordis.patch.yml has no placeholders or absolute paths', hardcoded.length === 0, hardcoded.join(','));
check('cordis.patch.yml mounts host dsh-presidio-pii', /name:\s*['"]?dsh-presidio-pii['"]?/m.test(patchRaw));
check('cordis.patch.yml mounts dsh-presidio-pii/guard', patchRaw.includes("name: 'dsh-presidio-pii/guard'"));
check('cordis.patch.yml mounts dsh-presidio-pii/fs', patchRaw.includes("name: 'dsh-presidio-pii/fs'"));
check('cordis.patch.yml uses dshHomePath for dataDir', patchRaw.includes("dshHomePath('data', 'presidio-pii')"));
check('cordis.patch.yml resolves skills via package', patchRaw.includes("resolve('dsh-presidio-pii/package.json')"));

// 4. resolveDataPaths & seeding in isolated dataDir
const { resolveDataPaths, ensureDefaultPreset, PKG_ROOT, DEFAULT_PRESET_TEMPLATE } = await import(
  pathToFileURL(join(BUNDLE_DIR, 'lib', 'paths.mjs')).href
);
check('PKG_ROOT resolves to plugins/dsh-presidio-pii', resolve(PKG_ROOT) === resolve(BUNDLE_DIR));
check('DEFAULT_PRESET_TEMPLATE exists', existsSync(DEFAULT_PRESET_TEMPLATE));

const workDir = mkdtempSync(join(tmpdir(), 'unified-pii-'));
try {
  const dataDir = join(workDir, 'store');
  const resolved = resolveDataPaths({ dataDir });
  check('resolveDataPaths honors explicit dataDir', resolved.dataDir === dataDir);
  check('presetFile inside dataDir', resolved.presetFile === join(dataDir, 'preset.json'));
  ensureDefaultPreset(resolved.presetFile, resolved.mode);
  check('ensureDefaultPreset seeds default preset.json', existsSync(resolved.presetFile));
  const seeded = JSON.parse(readFileSync(resolved.presetFile, 'utf8'));
  check('seeded preset.json has 20 entity_types', Array.isArray(seeded.entity_types) && seeded.entity_types.length === 20);
  check('seeded preset.json uses relative custom_rules_path', seeded.config?.custom_rules_path === 'user_terms_rules.json');

  // 5. Real engine redaction + restore via unified fs.mjs + dataDir (sid must be non-empty!)
  const fsMod = await import(pathToFileURL(join(BUNDLE_DIR, 'lib', 'fs.mjs')).href);
  fsMod.resetEngine();
  const tools = new Map();
  const mockFsCtx = {
    tools: {
      register(def) {
        tools.set(def.name, def);
        return () => tools.delete(def.name);
      },
    },
  };
  await fsMod.apply(mockFsCtx, { dataDir });
  check('fs module registers 4 tools', tools.size === 4);

  const sample = join(workDir, 'note.txt');
  const { writeFileSync } = await import('node:fs');
  writeFileSync(sample, '联系人：张伟，手机号 13800138000。', 'utf8');
  const rd = await tools.get('read_redacted').execute({ path: sample }, { cwd: workDir });
  check('read_redacted redacts phone without undefined sid', rd.text.includes('⟦PII:PHONE_NUMBER:') && !rd.text.includes('13800138000'), rd.text);
  check('read_redacted masks directory path', rd.displayPath === 'note.txt', rd.displayPath);

  const rs = await tools.get('restore').execute({ text: rd.text }, { cwd: workDir });
  check('restore recovers original phone from same session db', rs.text.includes('13800138000'), rs.text);

  // 6. Real terms.js apply with dataDir
  const termsMod = await import(pathToFileURL(join(BUNDLE_DIR, 'lib', 'terms.js')).href);
  const routes = new Map();
  const disposers = [];
  termsMod.apply({
    inject(_deps, cb) {
      cb({
        webServer: {
          register(r) {
            routes.set(r.path, r);
            return () => routes.delete(r.path);
          },
        },
        effect(fn) {
          const d = fn();
          if (typeof d === 'function') disposers.push(d);
        },
      });
    },
  }, { dataDir });
  check('terms module registers 6 routes with dataDir', routes.size === 6);
  check('terms module creates user_terms_rules.json in dataDir', existsSync(join(dataDir, 'user_terms_rules.json')));
  for (const d of disposers) d();
} finally {
  try {
    rmSync(workDir, { recursive: true, force: true });
  } catch {
    // Windows node:sqlite holds open db handle until process exit
  }
}

console.log(`\nSummary: ${passes} passed, ${failures} failed`);
assert.equal(failures, 0);
