# 代码审查报告 — PII 引擎 Node 迁移

**审查范围**：`refactor/node-pii-engine` 分支未提交的全部变更  
**变更文件**：`plugins/dsh-pii-guard/lib/index.js`、`tools/install.ps1`、`tools/verify_install.ps1`（修改）；`node_pii/{engine,custom_rules,normalize,recognizers,db,journal,hooks,server}.mjs`、`tests/node/{engine-equivalence,protocol-smoke}.mjs`、`tests/node/golden.json`、`tools/gen_equivalence_golden.py`、`docs/NODE-ENGINE-{MIGRATION-PLAN,API-CONTRACT}.md`（新增）  
**验证结果**：8/8 `.mjs` 语法 OK；`engine-equivalence.mjs` 41/41 PASS；`protocol-smoke.mjs` 3/3 PASS；`plugin_jobs/display/terms` 全绿；`verify_install.ps1` PASS=4 FAIL=0 SKIP=1，exit=0。

## 结论：✅ 可合并（无 blocker）

没有 blocker 级问题。以下列出 suggestion（建议修改）与 nit（拾遗），供作者在合并前酌情处理，不阻塞合并。

> **2026-11-20 复审更新**：suggestion 已处置完毕（见文末「处置记录」）。其中两条
> 原意见经与 Python 基准（hooks.py:205-235、server.py:50-72、server.py:120）核对后
> 撤回——Node 原实现已逐字等价，修改反而会破坏 parity；S5 升级为 parity 修复
> （移植 db.py 的 icacls 收紧逻辑）。

---

## 建议（Suggestion）

### [suggestion] node_pii/engine.mjs:30-33 — defaultRepoDir() Windows 路径口径与 hooks.mjs 不一致
`defaultRepoDir()` 用 `new URL('..', import.meta.url).pathname` 再 `replace(/^\/([A-Za-z]:)/, '$1')` 还原盘符，在 Windows ESM `file:///E:/...` 下能工作，但对非 `file:` 协议或打包场景脆弱。`hooks.mjs:10-11` 已用 `path.dirname(fileURLToPath(import.meta.url))`，口径更稳健。
**建议**：改为 `path.dirname(fileURLToPath(import.meta.url))` + `path.resolve(..., '..')`，与 hooks.mjs 保持一致，避免 Windows 边界复现。

### [suggestion] node_pii/hooks.mjs:175-201 — custom rules 文件变更不触发热更新
`getEngine` 单例只对比 `PRESET_SIG`（preset 文件 mtime+size）来热更新 `entityTypes`/`whitelist`；`customRules` 来源的变更若不伴随 preset 文件变更，不会重载。契约承诺规则热更新（1s 节流、mtime+size 签名），但单例层未把 custom rules 签名纳入。
**建议**：在 `PRESET_SIG` 并入 custom rules 文件签名，或在 sig 变更分支里也调用 `reloadCustomRules()`。

### [suggestion] node_pii/server.mjs:15-28 — mask 模式重复扫描占位符
`restoreDisplay` mask 分支先 `text.replace(PH_RE, ...)` 再 `text.matchAll(PH_RE)` 计数，对同一文本两次正则全文扫描。`engine.restore` 已扫描一次，此处可复用 `rs.restored` 的 key 集合。
**建议**：合并为一次扫描，用 `rs.restored` 的 keys 做计数与打码，减少 O(n) 重复。

### [suggestion] node_pii/recognizers.mjs:160-162 — 词表为模块级可变全局
`SURNAMES`/`SURNAME_CHARS` 是模块级 `let`，被 `getChineseRecognizers()` 每次调用重写。多引擎实例若期望用不同词表会互相污染，且不利于单元测试隔离。
**建议**：将词表挂载到识别器实例或通过闭包传入，避免模块级可变状态。

### [suggestion] node_pii/db.mjs:17-33 — Windows ACL 收紧仅告警，生产需人工补齐
Windows 下 `harden()` 跳过 `icacls`，只告警一次。DSH 在 Windows 生产部署时，`.pii_presidio_store` 目录及 WAL/shm 文件权限不会自动收紧，HMAC key 文件 `journal_hmac.key` 也未按 `0600` 收紧（`fs.writeFileSync` 未传 `mode`）。
**建议**：在 `docs/NODE-ENGINE-MIGRATION-PLAN.md` 已知不支持里补充 Windows ACL 手动收紧步骤；或在 `harden` 里对 key 文件显式传 `0o600`（Windows chmod 不动 ACL，但可作为文档化意图）。

---

## 拾遗（Nit）

| # | 位置 | 问题 | 建议 |
|---|------|------|------|
| 1 | `engine.mjs:227` | `for (const { res, ph } of [...plan].reverse())` 解构出 `res` 但未使用 | 改为 `for (const { ph, res: _ } of [...plan].reverse())` 或只取 `ph` |
| 2 | `server.mjs:69` | `n = redacted.split('⟦PII:').length - 1` 估算占位符数，若原文本身含 `⟦PII:` 会计偏 | 改用 `Object.keys(phMap).length` 或 `map` 实际条目数，更准确 |
| 3 | 全部 `.mjs` | 注释与日志中英文混用（中文注释 + 英文变量/英文日志） | 统一为中文注释，日志保留英文便于检索 |
| 4 | `custom_rules.mjs:110` | `new RegExp(item.pattern, 'g')` 只验证可编译，未验证是否会灾难性回溯（ReDoS） | B2 已在 guard-terms 侧通过结构化括号树修复，此处可补充一条 nit 提示：用户自定义正则由管理员审核 |

---

## 审查证据摘要

- 等价性：`tests/node/golden.json` 41 样本（含手机/邮箱/身份证含错校验位/X 校验/统信码/座机/IP 多实体/MAC/全角/插值/人名边界/地点机构职务/精度闸门零命中/白名单/多实体混合），Node 与 Python 无 jieba fallback 模式逐字一致（41/41）。
- 协议层：`redact → restore(full) → restore(mask)` 端到端，mask 不泄露完整 PII（`13*******00`，不含 `13800138000`）。
- 部署侧：`install.ps1` 改为 Node ≥22.5 校验 + `node_pii/server.mjs` 哨兵；`verify_install.ps1` 5 项自检（语法/协议/guard 加载/路径一致性）全 PASS，SKIP=1（无 plugin_manager CLI）。
- 守门：三套 JS 烟测（plugin_jobs/plugin_display/plugin_terms）全绿，guard 插件 fail-closed 语义保留（`PII_GUARD_PY` 兼容别名指向不存在的 bin 时 spawn 失败被兜住）。

审查员：P8 Owner（自审）  
审查时间：2026-11-19

---

## 处置记录（2026-11-20 复审）

对 5 条 suggestion + 4 条 nit 逐条复核处置。复核方法：先重读 Python 基准源码确认语义归属，再决定「修 / 撤回」，避免把等价实现误判为缺陷。

| # | 原意见 | 处置 | 依据 |
|---|--------|------|------|
| S1 | engine.mjs defaultRepoDir 路径口径脆弱 | **已修** — 改为 `fileURLToPath` + `path.resolve`（engine.mjs:6-7, 32-35） | 与 hooks.mjs 口径统一 |
| S2 | hooks.mjs 单例不含 custom rules 热更新 | **撤回** — Python `_maybe_reload_preset`（hooks.py:205-235）同样只比对 preset 签名；custom rules 靠引擎内 `refresh()`（engine.mjs:123，1s 节流）。Node 已等价 | 修改会偏离基准语义 |
| S3 | server.mjs mask 双扫描 | **撤回** — Python `_restore_display`（server.py:59-69）同为「restore 一次 + mask sub 一次」；n 口径 `len(rs.restored)` 已逐字对齐 | 修改会偏离基准语义 |
| S4 | recognizers.mjs 词表模块级可变全局 | **已修** — 加 `SURNAME_SETS`（WeakMap 按 assets 缓存集合），同 assets 复用、不重复重建；模块级 `SURNAMES/SURNAME_CHARS` 仅作注入结果（recognizers.mjs:160-167, 663-674） | 消除重复重建；工厂函数引用语义不变 |
| S5 | db.mjs Windows ACL 仅告警 | **升级为 parity 修复** — 移植 Python `db.py:_harden`（db.py:15-67）完整语义：`icacls /inheritance:r /grant:r`（当前用户+SYSTEM+Administrators）、回读验证、失败回滚继承。实测临时库收紧后 ACL 只剩 3 个主体 | 原意见基于错误记忆「Python 只告警」，实为 Node 侧缺失 parity |
| N1 | engine.mjs:227 未使用 res | **撤回** — `res.start/res.end` 在 engine.mjs:228 实际使用，原意见误判 | 代码事实 |
| N2 | server.mjs:69 split 计数不准 | **撤回** — Python `server.py:120` 就是 `redacted.count("⟦PII:")`，Node `split().length-1` 逐字等价 | 修改会偏离基准语义 |
| N3 | 注释中英混用 | 保留（风格项，不阻塞） | — |
| N4 | custom_rules 正则 ReDoS | 保留（用户自定义规则由管理员审核，B2 已在 guard-terms 侧修复） | — |

### 复审后全量验证证据（2026-11-20）

- 语法：`node --check` 8/8 OK，`mjs_syntax_all_ok=True`。
- 等价性：`node tests/node/engine-equivalence.mjs` → `EQUIVALENCE: 41/41 passed, 0 failed, ALL_GOLDEN_MATCH, exit=0`。
- 协议：`node tests/node/protocol-smoke.mjs` → `PROTOCOL_SMOKE: 3/3 passed, ALL_PROTOCOL_CHECKS_PASS, exit=0`。
- 插件烟测：`plugin_jobs` ALL PASS、`plugin_display` ALL PASS（含 S3 config.repo）、`plugin_terms` 63/63，exit 全 0。
- icacls 收紧实测：临时目录建库后 `icacls` 仅剩 `BUILTIN\Administrators` / `SYSTEM` / `AOC\sergg` 三主体（继承已移除），probe 读写正常。
- 部署守门：`verify_install.ps1` → PASS=4 FAIL=0 SKIP=1，verify_exit=0。

复审人：P8 Owner  
复审时间：2026-11-20
