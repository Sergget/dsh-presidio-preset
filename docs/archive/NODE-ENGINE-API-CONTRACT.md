# Node PII 引擎模块接口契约（并行实现基准）

所有 `node_pii/*.mjs` 用 ESM（`import` / `export`）。签名一旦定下不得单方改动；如需变更先改本文件并通知全组。

## 语义总基准
- 对齐 Python「无 jieba fallback」模式（见 `docs/NODE-ENGINE-MIGRATION-PLAN.md` §2）。
- 占位符 `⟦PII:<TYPE>:<SEQ:04d>⟧`；`⟦PII:` 计数即 `n`。
- 未知/无效 entity_types → fail toward 多脱敏（空集合 = 全开）。

---

## `node_pii/normalize.mjs`
```js
export class NormalizedText {
  constructor(text: string)
  // .text     : string             归一化后文本（注意：属性名是 text，对齐 Python normalize.py:146）
  // .origin   : number[]           归一化后每字符对应的原文下标（与 .text 等长）
  // .spans    : Array<[number,number]> 归一化后第 i 个字符在原文的 [start,end)
  // .changed  : boolean            text !== 输入文本
  back(start: number, end: number): [number, number]   // 等价 Python to_original
}
export function toOriginal(start, end, origin, spans): [number, number]
```
语义逐字对齐 `presidio_pii/normalize.py`：`_SEP_CHARS`（空格/Tab/CR/LF/不换行/全角/窄空格/零宽/连字符系列/ASCII hyphen/underscore，不含点号）、单字符 NFKC 折叠、`_trailing_is_complete_mobile` 禁吞、零宽并入前一 span、`to_original` 的 `max(orig_end, orig_start+1)`。

## `node_pii/recognizers.mjs`
```js
export class RecognizerResult {
  constructor(start: number, end: number, entity_type: string, score: number, recognizer?: string)
  // 属性同名；坐标是「原文」坐标
}
export function loadAssets(repoDir: string): {surnames: string[], adminAreas: string[], titles: string[]}
  // 读 <repoDir>/presidio_pii/assets/{surnames,admin_areas,titles}.txt，逐行 strip，去空行/BOM
export function getChineseRecognizers(assets): Recognizer[]
  // 返回 15 个识别器，顺序/类型对齐 Python get_chinese_recognizers()
  // 每个 recognizer 形如：
  // { name: string, entity_type?: string, supportedEntities?: string[],
  //   analyze(text: string): RecognizerResult[] }   ← 方法名是 analyze（对齐 Python engine.py:182）
  // 注：engine 侧做兼容调用 rec.analyze ?? rec.entities，两种命名都能对接。
  // 固定无 jieba：boundaries()/pos_tokens() 恒 null，is_common_word() 恒 false
```
识别器内部语义逐字对齐 `presidio_pii/chinese_recognizers.py` 全部正则常量与校验：_RE_ID(18位+校验位 _id_valid + _CITY_CODES/_WEIGHTS/_MOD_MAP)、_RE_ID15、_RE_MOBILE `1[3-9]\d{9}`、_RE_LANDLINE、_RE_EMAIL、_RE_CREDIT、_RE_BANK(Luhn + 13位毫秒排除)、_RE_PASSPORT、_RE_PLATE、_RE_IPV4、_RE_MAC；身份证/银行卡校验失败降级保留 score 0.70/0.45；人名/名单/地名/机构/职务的边界与黑名单逻辑照搬 fallback 分支。

## `node_pii/custom_rules.mjs`
```js
export class CustomRuleSet {
  constructor(opts?: {strict?: boolean, repoDir?: string})
  refresh(): boolean                  // 返回是否真的换过规则（对齐 Python custom_rules.py:379）
  get rules(): Recognizer[]           // JSON 正则规则识别器（对齐 Python .rules）
  get entityTypes(): string[]
  entityPriorities(): object          // 对齐 Python entity_priorities()
}
```
JSON 规则字段 `{name, entity_type, score, context_hint?, negative_hint?, priority (0-99 默认99)}`；捕获组取 group1；前方 20 字符窗口 hints 拒绝。按文件签名（mtime+size）热更新、1s 节流、失败保留上一份。**`.py` 代码规则忽略并 `console.warn`**（Node 无法等价执行）。

## `node_pii/db.mjs`
```js
export class SessionRegistry {
  constructor(dbPath: string)
  createSession(): string            // uuid4 hex 前 12
  addMapping(sid, docId, idx, ptype, placeholder, original, commit = true): void
  commit(): void
  getRestoreMap(sid, docId?): Array<{ptype, placeholder, original}>   // ORDER BY idx
  getMaxSeq(sid, ptype): number      // digitStart = 5 + len(ptype) + 2; MAX(CAST(SUBSTR(placeholder,?) AS INTEGER))
  deleteSession(sid): void
  close(): void
}
```
用 `node:sqlite` 的 `DatabaseSync`；schema 与 `presidio_pii/db.py` 完全一致（session + mapping 表 + 两个索引）；`PRAGMA journal_mode=WAL` + `synchronous=NORMAL`；目录/文件权限 FS chmod 0700/0600，Windows 跳过 ACL 仅告警不阻断。

## `node_pii/journal.mjs`
```js
export class JsonlJournal {
  constructor(path: string, maxBytes = 0)
  record(event: string, fields: object): void
  readAll(): object[]
}
```
`{ts: round(time,3), iso: 秒精度 ISO, event, ...fields}` → `JSON.stringify` + `\n`；轮转 `<name>.1`（先 unlink 再 rename），失败不阻塞写；`maxBytes<=0` 不限。

## `node_pii/hooks.mjs`
```js
export function sessionId(cid?: string): string      // sha1(cid).slice(0,12) 或 'daily-'+sha1(today).slice(0,8)
export function fingerprint(text: string): string    // HMAC-SHA256(key, text).slice(0,16)
export function maskValue(value: string, etype: string): string
export function beforeLlm(text, sid, docId?): {text: string, ...}   // 内部调 engine.redact + journal.record
export function afterLlm(text, sid, docId?): string
export function getEngine(cfg?): object              // lazy singleton，返回 engine.Engine 实例
export function resetSingleton(): void               // 测试用
```
配置优先级 env > preset.config > 默认；HMAC key = env `PII_DSH_LOG_HMAC_KEY` > `<db同目录>/journal_hmac.key`（随机生成 + 权限收紧）。`maskValue`：邮箱含 `@` → `local[0]+'***@'+domain`；len≤4 → `v[0]+'*'.repeat(len-1)`；否则 `v.slice(0,2)+'*'.repeat(len-4)+v.slice(-2)`。

## `node_pii/engine.mjs`（核心流水线，主代理实现）
```js
export class Engine {
  constructor(cfg: object)   // {recognizers, customRuleSet, registry, entityTypes, whitelist, hooks?}
  analyze(text: string): RecognizerResult[]
  redact(text, sid, docId?): {text, n_replaced, entity_counts, n_whitelisted, restored, session_id, doc_id}
  restore(text, sid, docId?, mode?): {restored: string, n: number}
  setEntityTypes(types: string[]): void
  reset(): void
}
```
流水线逐字对齐 `engine.py`：analyze→白名单 drop→`getMaxSeq` 全局递增→占位符→逆序替换→批量 addMapping→commit；`_resolve_overlaps` 排序 key=(-长度, priority, start) 贪心；restore 只替换文本中实际出现的占位符并去重。

## `node_pii/server.mjs`（入口脚本）
stdio `readline` 逐行 `JSON.parse`：
- `redact`（缺省）：`{id, text, sid}` → `{id, redacted, n, map}`（map 只含本次增量新占位符）
- `restore`：`{id, op:'restore', text, sid, mode:'full'|'mask'}` → `{id, restored, n}`
- 任何异常 → `{id, error: String(err)}`

`map` 生成：`before=registry.getRestoreMap(skey,'svc')` 快照 → `beforeLlm` → `after` 增量 diff（新 key 且 mode=mask 时 `maskValue`）；`skey = sessionId(sid)`。
