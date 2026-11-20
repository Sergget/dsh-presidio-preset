// Node 引擎 vs Python golden 逐字等价性测试
// golden.json 由 tools/gen_equivalence_golden.py 在强制无 jieba 模式下生成。
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { Engine } from '../../node_pii/engine.mjs';
import { SessionRegistry } from '../../node_pii/db.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '../..');
const GOLDEN = JSON.parse(fs.readFileSync(path.join(HERE, 'golden.json'), 'utf8'));

let passed = 0, failed = 0;
const failures = [];

for (const g of GOLDEN) {
  const registry = new SessionRegistry(':memory:');
  const sid = registry.createSession();
  const engine = new Engine({ repoDir: REPO, registry, whitelist: g.whitelist });
  try {
    const rd = engine.redact(g.text, sid, 'golden');
    const checks = [
      ['redacted', rd.text, g.redacted],
      ['n', rd.n_replaced, g.n],
      ['map', rd.restored, g.map],
      ['entity_counts', rd.entity_counts, g.entity_counts],
      ['n_whitelisted', rd.n_whitelisted, g.n_whitelisted],
    ];
    const errs = [];
    for (const [name, actual, expected] of checks) {
      try { assert.deepStrictEqual(actual, expected); }
      catch { errs.push(`${name}: actual=${JSON.stringify(actual)} expected=${JSON.stringify(expected)}`); }
    }
    if (errs.length) {
      failed++;
      failures.push(`#${g.id} "${g.text}"\n    ${errs.join('\n    ')}`);
    } else {
      passed++;
    }
  } catch (ex) {
    failed++;
    failures.push(`#${g.id} "${g.text}" THREW ${ex.stack || ex.message}`);
  } finally {
    engine.reset();
  }
}

console.log(`\nEQUIVALENCE: ${passed}/${GOLDEN.length} passed, ${failed} failed`);
if (failures.length) {
  console.log('\nFAILURES:\n' + failures.join('\n'));
  process.exit(1);
}
console.log('ALL_GOLDEN_MATCH');
