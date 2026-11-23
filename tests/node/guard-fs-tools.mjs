// Phase 1.1 四件套插件回归：read_redacted / write_raw / restore / ls
// 覆盖 D3（抹 displayPath）+ 自限长（防 spill）+ redact/restore 接线。
//
// 运行：node tests/node/guard-fs-tools.mjs

import { mkdtempSync, writeFileSync, readFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  readRedacted,
  writeRaw,
  restoreText,
  listDir,
  setRedact,
  setRestore,
  sanitizePath,
  MAX_READ_CHARS,
  MAX_LS_ENTRIES,
  TOOL_DEFS,
  name,
  inject,
} from '../../plugins/dsh-presidio-pii/lib/fs.mjs';

let passed = 0;
let failed = 0;
function ok(label, cond, extra) {
  if (cond) {
    passed += 1;
    console.log(`  ok   ${label}`);
  } else {
    failed += 1;
    console.log(`  FAIL ${label}${extra === undefined ? '' : ` :: ${JSON.stringify(extra)}`}`);
  }
}

const dir = mkdtempSync(join(tmpdir(), 'guard-fs-test-'));
const ctx = { cwd: dir };

// 桩：把手机号替换成占位符
setRedact((text) => text.replace(/1[3-9]\d{9}/g, '⟦PII:PHONE_NUMBER:0001⟧'));
setRestore((text) => text.replace(/⟦PII:PHONE_NUMBER:0001⟧/g, '13800138000'));

console.log('[1] 插件表面');
ok('name 为 pii-guard-fs', name === 'pii-guard-fs');
ok('inject 含 tools', Array.isArray(inject) && inject.includes('tools'));
ok('注册 4 个工具', TOOL_DEFS.length === 4, TOOL_DEFS.map((t) => t.name));
ok(
  '工具名为契约名字',
  TOOL_DEFS.map((t) => t.name).join(',') === 'read_redacted,write_raw,restore,ls',
  TOOL_DEFS.map((t) => t.name),
);
ok(
  '每个工具都有 output.render',
  TOOL_DEFS.every((t) => typeof t.output?.render === 'function'),
);

console.log('[2] read_redacted：脱敏 + 抹路径');
const sample = join(dir, 'secret-project', 'note.txt');
mkdirSync(join(dir, 'secret-project'), { recursive: true });
writeFileSync(sample, '联系人 张伟，手机 13800138000。', 'utf8');
const r1 = await readRedacted(ctx, { path: sample });
ok('返回占位符而非原文', r1.text.includes('⟦PII:PHONE_NUMBER:0001⟧'), r1.text);
ok('原文手机号不泄漏', !r1.text.includes('13800138000'), r1.text);
ok('displayPath 只留 basename', r1.displayPath === 'note.txt', r1.displayPath);
ok('不泄漏目录名 secret-project', !JSON.stringify(r1).includes('secret-project'));
ok('totalLength 为原文长度', r1.totalLength === '联系人 张伟，手机 13800138000。'.length);
ok('未截断', r1.truncated === false);

console.log('[3] read_redacted：超长自限长（防 spill）');
const big = join(dir, 'big.txt');
writeFileSync(big, 'A'.repeat(MAX_READ_CHARS + 5000), 'utf8');
const r2 = await readRedacted(ctx, { path: big });
ok('超长被截断', r2.truncated === true);
ok('返回长度不超过上限', r2.text.length === MAX_READ_CHARS, r2.text.length);
ok('totalLength 记录原始长度', r2.totalLength === MAX_READ_CHARS + 5000);

console.log('[4] read_redacted：错误路径不泄漏目录');
const r3 = await readRedacted(ctx, { path: join(dir, 'secret-project', 'missing.txt') });
ok('返回错误对象', typeof r3.error === 'string');
ok('error 不含绝对目录', !r3.error.includes(dir), r3.error);
ok('displayPath 为 <redacted>', r3.displayPath === '<redacted>');

console.log('[5] write_raw：落盘 + 相对路径 + 限长');
const w1 = await writeRaw(ctx, { path: 'out/restored.txt', text: '手机 13800138000' });
ok('写入成功', w1.written === '手机 13800138000'.length, w1);
ok('displayPath 只留 basename', w1.displayPath === 'restored.txt');
ok('磁盘内容为原文', readFileSync(join(dir, 'out', 'restored.txt'), 'utf8') === '手机 13800138000');
const w2 = await writeRaw(ctx, { path: 'out/huge.txt', text: 'B'.repeat(500_001) });
ok('超长写入被截断', w2.truncated === true);
const w3 = await writeRaw(ctx, { path: 'x.txt' });
ok('缺 text 报错', typeof w3.error === 'string');

console.log('[6] restore：占位符还原');
const s1 = await restoreText(ctx, { text: '手机 ⟦PII:PHONE_NUMBER:0001⟧' });
ok('还原成原文', s1.text === '手机 13800138000', s1.text);
ok('restore 的 displayPath 恒为 <redacted>', s1.displayPath === '<redacted>');

console.log('[7] ls：条目 + 抹路径 + 上限');
mkdirSync(join(dir, 'many'), { recursive: true });
for (let i = 0; i < MAX_LS_ENTRIES + 3; i += 1) writeFileSync(join(dir, 'many', `f${i}.txt`), 'x');
const l1 = await listDir(ctx, { path: join(dir, 'many') });
ok('条目被截断', l1.truncated === true && l1.count === MAX_LS_ENTRIES, l1.count);
ok('totalEntries 为真实数量', l1.totalEntries === MAX_LS_ENTRIES + 3);
ok('displayPath 只留 basename', l1.displayPath === 'many');
const l2 = await listDir(ctx, { path: sample });
ok('非目录报错', typeof l2.error === 'string' && l2.error.includes('not a directory'));

console.log('[8] D3：sanitizePath 兜底');
ok('空值兜底', sanitizePath('') === '<unknown>');
ok('非字符串兜底', sanitizePath(undefined) === '<unknown>');
ok('Windows 路径取 basename', sanitizePath('C:\\Users\\alice\\docs\\a.txt') === 'a.txt');

console.log('[9] fail-closed：redact 抛错时不直通原文');
setRedact(() => {
  throw new Error('engine down');
});
const r4 = await readRedacted(ctx, { path: sample });
ok('抛出被捕获为 error', typeof r4.error === 'string');
ok('绝不返回原文', r4.text === undefined, r4);

rmSync(dir, { recursive: true, force: true });

console.log(`\nGUARD_FS_TOOLS ${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
else console.log('ALL_GUARD_FS_CHECKS_PASS');
