# Node PII 引擎（权威文档）

> **合并说明（2026-11-20）**：本文档合并自四份迁移期文档——`NODE-ENGINE-MIGRATION-PLAN.md`（方案）、`NODE-ENGINE-API-CONTRACT.md`（接口契约）、`FINAL-MIGRATION-REPORT.md`（最终报告）、`CODE-REVIEW-REPORT.md`（审查与处置）。四份原件已移入 [archive/](archive/)，内容以本文为准。方案期文档中的计划口吻（"实施顺序"、"验收标准"）已改写为现状描述。

**状态**：✅ 已全部实施并验收通过。分支 `refactor/node-pii-engine`。
**一句话**：`presidio_pii` Python 引擎已完整迁移为 `node_pii/` 下 8 个零依赖 ESM 模块，guard 插件不再 spawn Python，仅 dsh + Node 宿主机可离线安装。

---

## 1. 目标与硬约束

- **协议不变**：server 的 stdio JSON 行协议逐字兼容（`redact` / `restore` / `error`）。
- **行为等价**：与 Python 引擎在**同一基准模式**（无 jieba fallback）下输出逐字一致。
- **存储兼容**：复用现有 SQLite schema（`.pii_presidio_store/sessions.db`），Node 用内置 `node:sqlite`，零迁移。
- **零外部依赖**：只用 Node 标准库 + 仓库内词表；不引入 nodejieba 等任何 npm 包。

## 2. 关键决策（含理由）

1. **分词基准 = Python「无 jieba fallback」模式**。jieba 0.42.1 是 `pyproject.toml` 的 optional 依赖；`segmentation.py:5` 明确设计无 jieba 时回退启发式；`tests/test_roster_person.py` 双模式均通过。Node 对齐 fallback 分支：`boundaries()`/`pos_tokens()` 恒 null、`is_common_word()` 恒 false；等价性 golden 用 Python 强制 `segmentation._HAS_JIEBA=False` 生成。**代价**：生产装 jieba 时 Python 版精度略高（nr/ns 词性过滤），已知且可接受——Node 版满足全部回归用例。
2. **索引口径：JS UTF-16 code unit**。中文均在 BMP，与 Python 字符下标等价；emoji 增补平面未做代理对拆分（基准无此场景）。
3. **事务语义：显式 BEGIN/COMMIT**。node:sqlite 默认 autocommit；`db.mjs` 显式维护事务边界以复刻 `addMapping(commit=false) + commit()` 批量提交。
4. **Windows ACL：与 Python `_harden` 完整 parity**（2026-11-20 复审 S5 升级修复后）。`db.mjs` 移植 `db.py:15-67` 全语义：`icacls /inheritance:r /grant:r`（当前用户+SYSTEM+Administrators）、回读验证、失败回滚继承；实测临时库收紧后 ACL 只剩 3 个主体。早期"仅告警"口径已作废。

## 3. 交付物

### 引擎（`node_pii/`，8 模块）

| 文件 | 职责 |
|------|------|
| `engine.mjs` | 核心流水线：analyze → 白名单 drop → 过滤 → 裁剪 → 去重叠 → 占位符替换 → 映射登记 |
| `recognizers.mjs` | 15 个中文识别器（身份证/15位证/手机/座机/邮箱/统信码/银行卡/护照/车牌/IP+MAC/人名/人名库/地点/机构/职务） |
| `normalize.mjs` | 归一化（NFKC、数字间分隔符吞噬、手机号拆分闸门）、坐标原文回映射 |
| `custom_rules.mjs` | JSON 自定义正则规则，热更新（mtime+size 签名、1s 节流）、优先级取最小 |
| `db.mjs` | SQLite（node:sqlite）映射登记，WAL+NORMAL，`getMaxSeq` 按 (session, ptype)，Windows icacls 收紧 |
| `journal.mjs` | JSONL 审计日志，按字节轮转，跳过坏行 |
| `hooks.mjs` | 会话 ID / HMAC 指纹 / preset 配置加载（env > preset > 默认）、beforeLlm/afterLlm |
| `server.mjs` | stdio JSON 行协议常驻服务（redact / restore full / restore mask） |

### 测试与工具

| 文件 | 职责 |
|------|------|
| `tests/node/golden.json` | 41 组等价性样本（Python 强制无 jieba 生成） |
| `tests/node/engine-equivalence.mjs` | Node vs Python golden 逐字比对（redacted/n/map/entity_counts/n_whitelisted） |
| `tests/node/protocol-smoke.mjs` | redact → restore(full) → restore(mask) 端到端协议 smoke |
| `tools/gen_equivalence_golden.py` | golden 生成脚本（强制 `_HAS_JIEBA=False`） |

### 去 Python 化改造

| 文件 | 变更 |
|------|------|
| `plugins/dsh-pii-guard/lib/index.js` | spawn 目标 `python server.py` → `NODE_BIN node_pii/server.mjs`（`PII_GUARD_NODE` env / 兼容 `PII_GUARD_PY` / `process.execPath` 兜底）；哨兵文件 `server.py` → `server.mjs` |
| `tools/install.ps1` | Python 3.9~3.13 版本校验 → Node ≥22.5 + node:sqlite 可用性校验 + `node_pii/server.mjs` 哨兵；UTF-8 BOM |
| `tools/verify_install.ps1` | 第 1 项 `node --check node_pii/server.mjs`、第 2 项协议 smoke；UTF-8 BOM |

## 4. 接口契约（签名摘要）

> 完整语义逐字对齐 `presidio_pii/` 对应 Python 模块；此处只列签名。

- `normalize.mjs`：`class NormalizedText { constructor(text); get text; get origin: number[]; get spans; get changed; back(start, end) }`；`toOriginal(start, end, origin, spans)`。属性名是 `.text`（对齐 `normalize.py:146`），`.origin` 是原文下标数组。
- `recognizers.mjs`：`class RecognizerResult { constructor(start, end, entity_type, score, recognizer?) }`（原文坐标）；`loadAssets(repoDir)` 读 `presidio_pii/assets/{surnames,admin_areas,titles}.txt`；`getChineseRecognizers(assets)` 返回 15 个识别器，统一 `analyze(text): RecognizerResult[]`（engine 侧兼容 `rec.analyze ?? rec.entities`）。词表集合经 `SURNAME_SETS`（WeakMap 按 assets 缓存）复用。
- `custom_rules.mjs`：`class CustomRuleSet { constructor({strict?, repoDir?}); refresh(): boolean; get rules; get entityTypes; entityPriorities() }`。JSON 规则字段 `{name, entity_type, score, context_hint?, negative_hint?, priority(0-99 默认99)}`；捕获组取 group1；前方 20 字符 hints 窗口。`.py` 代码规则忽略并告警。
- `db.mjs`：`class SessionRegistry { constructor(dbPath); createSession(); addMapping(sid, docId, idx, ptype, placeholder, original, commit=true); commit(); getRestoreMap(sid, docId?); getMaxSeq(sid, ptype); deleteSession(sid); close() }`。
- `journal.mjs`：`class JsonlJournal { constructor(path, maxBytes=0); record(event, fields); readAll() }`。
- `hooks.mjs`：`sessionId(cid?)`（sha1[:12] / `daily-`+sha1[:8]）；`fingerprint(text)`（HMAC-SHA256[:16]）；`maskValue(value, etype)`（邮箱 local[0]+`***`@domain；len≤4 首字符+`*`×(n-1)；否则前2+`*`×(n-4)+后2）；`getEngine(cfg?)` 单例（preset 签名热更新，仅比对 preset 文件——与 Python `hooks.py:205-235` 等价）；`beforeLlm/afterLlm`；`resetSingleton()`。
- `engine.mjs`：`class Engine { constructor(cfg); analyze(text); redact(text, sid, docId?); restore(text, sid, docId?, mode?); setEntityTypes(types); reloadCustomRules(); setWhitelist(...); reset() }`。
- `server.mjs` 协议：`redact` → `{id, redacted, n, map}`（map 只含本次增量新占位符；`n` 用 `redacted.count("⟦PII:")` 口径，`split().length-1` 逐字等价 Python `server.py:120`）；`restore`（mode full/mask）→ `{id, restored, n}`；异常 → `{id, error}`。mask 模式对**原始 text 的占位符**打码（原文不过显示侧——P1 泄露修复）。

## 5. 关键语义清单（与 Python 逐项对齐）

- 占位符 `⟦PII:<TYPE>:<SEQ:04d>⟧`，`SEQ` 按 (session+type) 全局递增（`getMaxSeq`）。
- `_PRIO` 优先级表 13 项（`engine.py:39-42`），自定义类型兜底 99。
- 重叠消解：先长度（长优先）、等长比优先级、再比起点；贪心不重叠；末尾按 start 还原。
- 白名单：区间相交 `r.start < e && r.end > s` 丢弃；UUID span 内实体整体跳过。
- entity_types：空集合 = 全开；未知类型告警忽略；全无效归空 = 全开（fail toward 多脱敏，B4 修复语义）；自定义规则类型始终保留。
- 归一化分隔符集合不含点号；仅夹在两数字间且单字符才吞；完整 11 位手机号右侧禁吞。
- server redact 只下发增量 map（diff `before_keys`）；restore 只替换文本中实际出现的占位符并去重。

## 6. 验收证据（全绿）

| # | 标准 | 结果 | 证据 |
|---|------|------|------|
| 1 | golden 逐字一致 | ✅ 41/41 | `node tests/node/engine-equivalence.mjs` → `EQUIVALENCE: 41/41 passed, ALL_GOLDEN_MATCH` |
| 2 | JSON-RPC 协议一致 | ✅ 3/3 | `node tests/node/protocol-smoke.mjs` → `PROTOCOL_SMOKE: 3/3 passed` |
| 3 | JS 插件烟测 | ✅ 全绿 | `plugin_jobs` / `plugin_display` / `plugin_terms`（75/75）ALL PASS |
| 4 | install.ps1 去 Python | ✅ | 真跑 exit=0；`verify_install.ps1` PASS=4 FAIL=0 SKIP=1 |
| 5 | pytest 保持绿 | ✅ 260 passed | Python 引擎保留（等价性基准与 CLI 仍需） |
| 6 | 报告落盘 | ✅ | 本文档（原四份已归档） |

## 7. 审查处置记录（2026-11-20 复审）

对 5 suggestion + 4 nit 逐条复核；方法：先重读 Python 基准源码确认语义归属，再决定「修 / 撤回」，避免把等价实现误判为缺陷。

| # | 原意见 | 处置 | 依据 |
|---|--------|------|------|
| S1 | engine.mjs defaultRepoDir 路径口径脆弱 | **已修** — `fileURLToPath` + `path.resolve`（与 hooks.mjs 统一） | engine.mjs:6-7, 32-35 |
| S2 | hooks.mjs 单例不含 custom rules 热更新 | **撤回** — Python `_maybe_reload_preset`（hooks.py:205-235）同样只比对 preset 签名；custom rules 靠引擎内 `refresh()`（1s 节流） | 修改会偏离基准语义 |
| S3 | server.mjs mask 双扫描 | **撤回** — Python `_restore_display`（server.py:59-69）同为 restore+mask 两次处理；n 口径已逐字对齐 | 修改会偏离基准语义 |
| S4 | recognizers.mjs 词表模块级可变全局 | **已修** — `SURNAME_SETS` WeakMap 按 assets 缓存；模块级变量仅作注入结果 | recognizers.mjs:160-167, 663-674 |
| S5 | db.mjs Windows ACL 仅告警 | **升级为 parity 修复** — 移植 Python `db.py:_harden` 完整语义（icacls /inheritance:r /grant:r 三主体、回读验证、失败回滚） | 原意见基于「Python 只告警」的错误记忆，实为 Node 侧缺失 parity |
| N1 | engine.mjs:227 未使用 res | **撤回** — `res.start/res.end` 在下一行实际使用 | 误判 |
| N2 | server.mjs split 计数不准 | **撤回** — Python `server.py:120` 就是 `redacted.count("⟦PII:")`，Node 逐字等价 | 修改会偏离基准语义 |
| N3 | 注释中英混用 | 保留（风格项，不阻塞） | — |
| N4 | custom_rules 正则 ReDoS | 保留（用户自定义规则由管理员审核；guard-terms 侧 B2 已用结构化括号树修复） | — |

另：开发期发现并修复 **mask 输出泄露 P1**——`server.mjs` mask 分支曾对 restore 后文本打码（找不到占位符 → 原样输出完整 PII），已改为对原始 text 的占位符打码，原文不过显示侧。

## 8. 已知不支持 / 与 Python 版差异

- **jieba 精度增益**：不在范围，永久采用 fallback 模式（见 §2.1）。
- **Python 代码规则（`.py` 自定义 analyze()）**：Node 无法等价执行，忽略并告警；JSON 正则规则完整支持。实际使用 `.py` 规则需人工转写为 JSON。
- **CLI Office 文档脱敏**（`python -m presidio_pii.cli`）：不在迁移范围（独立 CLI 功能，依赖 python-docx/pptx/openpyxl），保留 Python 脚本，不影响 guard 零 Python 目标。
- emoji 增补平面代理对未拆分（基准无此场景，可追加）。

## 9. 配置与环境变量

| 变量 | 作用 |
|------|------|
| `PII_GUARD_REPO` / bundle `config.repo` | 仓库根（server.mjs 定位词表与 db）；`config.repo` > env > 推断 > 默认 |
| `PII_GUARD_NODE`（兼容名 `PII_GUARD_PY`） | spawn 的 Node 可执行文件，缺省 `process.execPath` |
| `PII_DSH_DB_PATH` | SQLite 路径（默认 `<repo>/.pii_presidio_store/sessions.db`） |
| `PII_DSH_PRESET` / preset.json | entity_types / whitelist_path / custom_rules_path |
| `PII_DSH_ENTITY_TYPES` / `PII_DSH_WHITELIST` / `PII_DSH_CUSTOM_RULES` | env 覆盖 |
| `PII_DSH_LOG_HMAC_KEY` | HMAC 密钥；否则 `<db同目录>/journal_hmac.key`（随机生成 + ACL 收紧） |
| `PII_GUARD_DISPLAY` / `PII_GUARD_FAIL_OPEN` / shell 相关 | guard 插件层处理，不在 server 层 |

## 10. 历史文档

四份原件（方案 / 契约 / 最终报告 / 审查报告）已移入 [archive/](archive/)：`NODE-ENGINE-MIGRATION-PLAN.md`、`NODE-ENGINE-API-CONTRACT.md`、`FINAL-MIGRATION-REPORT.md`、`CODE-REVIEW-REPORT.md`。项目级历史审查见 [archive/CODE-REVIEW-20261118.md](archive/CODE-REVIEW-20261118.md)、[archive/CODE-REVIEW-20261119.md](archive/CODE-REVIEW-20261119.md)。
