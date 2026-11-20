// tests/node/preset-runtime-types.mjs — 生产配置集成测试（不是"测试里显式传规则"的自证）
//
// 事故背景：Phase 0 补齐 7 类扩展字段后，golden 与门禁都通过，但真实启动时报
//   [pii] 忽略未知实体类型 ["AGE",...,"IM_ACCOUNT"]
// 因为运行时引擎只读了 preset 的 custom_rules_path（用户词表），内置规则库
// rule_libraries/*.json 从未加载 —— 断言了一套生产不用的配置。
//
// 本测试只走生产路径：PII_DSH_PRESET → hooks.getEngine() → redact。
// 用法: node tests/node/preset-runtime-types.mjs
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const PRESET = path.join(REPO, '.agent-presets', 'presidio-pii', 'preset.json');
const EXTENDED = path.join(REPO, 'rule_libraries', 'extended-fields.json');

let pass = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) { pass += 1; console.log(`PASS ${name}`); }
  else { failures.push(`${name}${detail ? ` :: ${detail}` : ''}`); console.log(`FAIL ${name}${detail ? ` :: ${detail}` : ''}`); }
}

// ---- 只配置生产会配置的东西 ----
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pii-runtime-'));
const dbPath = path.join(tmp, 'sessions.db');
process.env.PII_DSH_PRESET = PRESET;
process.env.PII_DSH_DB_PATH = dbPath;
process.env.PII_DSH_LOG_PATH = '0'; // 关掉 journal，别在临时目录留垃圾
delete process.env.PII_DSH_CUSTOM_RULES; // 生产没有这个 env
delete process.env.PII_DSH_WHITELIST;

// 抓 stderr：断言不再出现"忽略未知实体类型"
const stderrChunks = [];
const origWrite = process.stderr.write.bind(process.stderr);
process.stderr.write = (chunk, ...rest) => {
  stderrChunks.push(String(chunk));
  return true;
};
const origError = console.error;
console.error = (...args) => { stderrChunks.push(args.map(String).join(' ')); };

const preset = JSON.parse(fs.readFileSync(PRESET, 'utf8').replace(/^\uFEFF/, ''));
const declared = preset.entity_types ?? [];

const { getEngine, resetSingleton } = await import(pathToFileURL(path.join(REPO, 'node_pii', 'hooks.mjs')).href);
resetSingleton();
const engine = getEngine();

// 恢复输出通道，后续打印走原始 stderr
process.stderr.write = origWrite;
console.error = origError;

// ---- 1. 引擎必须认得 preset 声明的每一个类型 ----
const known = engine._knownEntityTypes();
const missing = declared.filter((t) => !known.has(t));
check('preset 声明的 20 类全部为引擎已知类型', missing.length === 0, `缺少=${missing.join(',')}`);

// ---- 2. 内置规则库确实进了规则集（而不是只看类型名） ----
const ruleSources = String(engine._ruleSet?.sources ?? '');
check('规则源包含内置库 extended-fields.json',
  ruleSources.split(/[;,]/).some((p) => p.trim().endsWith(path.join('rule_libraries', 'extended-fields.json'))),
  `sources=${ruleSources || '(empty)'}`);
const rules = engine._ruleSet?.rules ?? [];
const libRuleTypes = new Set(rules.map((r) => r.entity_type));
check('规则集含 7 类扩展字段规则',
  ['AGE', 'BIRTH_DATE', 'GENDER', 'ETHNICITY', 'EDUCATION', 'IM_ACCOUNT', 'EMPLOYEE_ID']
    .every((t) => libRuleTypes.has(t)),
  `实际=${[...libRuleTypes].sort().join(',')}`);
check('内置库文件存在', fs.existsSync(EXTENDED));

// ---- 3. 生产路径 redact 真能产出这 7 类 ----
const SAMPLE = [
  '年龄 45 周岁，身体健康。',
  '出生日期：1990-03-07。',
  '性别：男，民族：汉族。',
  '学历：硕士研究生。',
  '微信：zhangsan2024 常联系。',
  '工号：EMP-000123 请登记。',
  '联系电话 13800138000，身份证 110101199003077890。',
].join('\n');
const rd = engine.redact(SAMPLE, 'runtime-test', 'prompt');
const gotTypes = Object.keys(rd.entity_counts ?? rd.entityCounts ?? {});
const expectTypes = ['AGE', 'BIRTH_DATE', 'GENDER', 'ETHNICITY', 'EDUCATION', 'IM_ACCOUNT', 'EMPLOYEE_ID', 'PHONE_NUMBER', 'ID_NUMBER'];
const gotMissing = expectTypes.filter((t) => !gotTypes.includes(t));
check('redact 命中 7 类扩展字段 + 2 类存量字段', gotMissing.length === 0, `未命中=${gotMissing.join(',')} 实际=${gotTypes.join(',')}`);

// ---- 4. 没有"未知实体类型"告警 ----
const joined = stderrChunks.join('');
check('无 [pii] 忽略未知实体类型 告警', !joined.includes('忽略未知实体类型'), joined.trim().slice(0, 300));

// ---- 5. 扩展字段真的被替换成占位符（不是仅归类）----
const redactedText = rd.text ?? rd.redacted ?? '';
check('扩展字段值已脱敏', !redactedText.includes('1990-03-07') && !redactedText.includes('zhangsan2024') && !redactedText.includes('EMP-000123'),
  redactedText.slice(0, 200));

// ---- 6. 还原无损（占位符 ↔ 原文）----
const rs = engine.restore(redactedText, 'runtime-test', 'prompt');
check('restore 还原原文', rs.text === SAMPLE, rs.text.slice(0, 120));

engine.reset?.();
fs.rmSync(tmp, { recursive: true, force: true });

console.log('');
if (failures.length) {
  console.log(`PRESET_RUNTIME_TYPES FAILED ${failures.length} 项:`);
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
console.log(`PRESET_RUNTIME_TYPES_PASS ${pass} 项检查全部通过`);
