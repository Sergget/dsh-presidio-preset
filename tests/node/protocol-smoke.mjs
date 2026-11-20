// Node server.mjs 协议层端到端 smoke：redact → restore(full) → restore(mask)
// 用独立临时 db/log + 占位 HMAC key，不污染工作树、不落真实密钥。
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '../..');
const SERVER = path.join(REPO, 'node_pii', 'server.mjs');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'pii-node-proto-'));

const env = {
  ...process.env,
  PII_DSH_DB_PATH: path.join(TMP, 'sessions.db'),
  PII_DSH_LOG_PATH: path.join(TMP, 'hook_log.jsonl'),
  PII_DSH_LOG_HMAC_KEY: 'test-placeholder-key-not-a-secret',
  PII_DSH_PRESET: path.join(TMP, 'nonexistent-preset.json'),
  PII_DSH_ENTITY_TYPES: '',
  PII_DSH_WHITELIST: '',
  PII_DSH_CUSTOM_RULES: '',
};

function run(requests) {
  const input = requests.map((r) => JSON.stringify(r)).join('\n') + '\n';
  const res = spawnSync(process.execPath, [SERVER], {
    input, encoding: 'utf8', env, cwd: REPO, timeout: 30000,
  });
  if (res.status !== 0) throw new Error(`server exit ${res.status}: ${res.stderr}`);
  return res.stdout.trim().split('\n').filter(Boolean).map((ln) => JSON.parse(ln));
}

let passed = 0;
function check(name, fn) {
  try { fn(); passed++; console.log(`  PASS ${name}`); }
  catch (e) { console.log(`  FAIL ${name}: ${e.message}`); throw e; }
}

const text = '手机号13800138000，邮箱 a.b@example.com，身份证 110101199003077890';

// 三条请求必须共用同一 sid（同一进程、同一映射库），占位符才能还原
const out = run([
  { id: 'r1', text, sid: 'smoke-1' },
  { id: 'r2', op: 'restore', text: '⟦PII:PHONE_NUMBER:0001⟧', sid: 'smoke-1', mode: 'full' },
  { id: 'r3', op: 'restore', text: '手机⟦PII:PHONE_NUMBER:0001⟧', sid: 'smoke-1', mode: 'mask' },
]);

check('redact 返回三条占位符且 n>=3', () => {
  assert.equal(out[0].id, 'r1');
  assert.equal(out[0].error, undefined);
  assert.ok(out[0].n >= 3, `n=${out[0].n}`);
  assert.ok(out[0].redacted.includes('⟦PII:PHONE_NUMBER:'));
  assert.ok(out[0].redacted.includes('⟦PII:EMAIL_ADDRESS:'));
  assert.ok(out[0].redacted.includes('⟦PII:ID_NUMBER:'));
  assert.ok(Object.keys(out[0].map).length >= 3);
});

check('restore full 还原完整原文', () => {
  assert.equal(out[1].restored, '13800138000');
  assert.equal(out[1].n, 1);
});

check('restore mask 打码且不泄露完整 PII', () => {
  const masked = out[2].restored;
  assert.equal(out[2].n, 1);
  // maskValue 对齐 Python v[:2]+'*'*(len-4)+v[-2:] → 13800138000(11位) = 13 + 7个* + 00
  assert.ok(masked.includes('13*******00'), `masked=${masked}`);
  assert.ok(!masked.includes('13800138000'), `LEAK! masked=${masked}`);
});

fs.rmSync(TMP, { recursive: true, force: true });
console.log(`\nPROTOCOL_SMOKE: ${passed}/3 passed`);
if (passed !== 3) process.exit(1);
console.log('ALL_PROTOCOL_CHECKS_PASS');
