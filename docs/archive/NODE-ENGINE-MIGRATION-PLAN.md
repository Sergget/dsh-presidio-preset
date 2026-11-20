# Node PII 引擎迁移方案（refactor/node-pii-engine）

## 1. 目标与硬约束

**目标**：用 Node/JS 重写 `presidio_pii` 脱敏引擎，彻底去除 guard 运行时的 Python 前置依赖，让宿主机只要有 dsh（必带 Node ≥24.9）即可离线安装运行。

**硬约束**：
- **协议不变**：server 的 stdio JSON 行协议逐字兼容（`redact` / `restore` / `error`）。
- **行为等价**：与 Python 引擎在**同一基准模式**下输出一致（见 §2 分词基准）。
- **存储兼容**：复用现有 SQLite schema（`.pii_presidio_store/sessions.db`），Node 用内置 `node:sqlite`（v24 无 flag 可用，已实测），零迁移。
- **零外部依赖**：只用 Node 标准库 + 仓库内词表文件；不引入 nodejieba（需原生编译）等任何 npm 包。

## 2. 关键技术决策：分词基准 = Python「无 jieba fallback」模式

**背景**：`segmentation.py` 依赖可选 jieba 做中文分词（nr 人名 / ns 地名 / 词边界对齐）。Node 生态无 jieba 等价物。

**取证**：
- jieba 0.42.1 已安装，是 `pyproject.toml:22-23` 的 optional `segment` 依赖。
- `segmentation.py:5` 明确设计：无 jieba 时"自动回退到启发式规则，功能不受影响"。
- `tests/test_roster_person.py:99-109` 专门验证「有/无 jieba 双模式」均通过。

**决策**：Node 引擎对齐 Python **无 jieba fallback 模式**：
- `segmentation.boundaries()` → `null`，`pos_tokens()` → `null`，`is_common_word()` → `false`。
- 人名走 `ChinesePersonRecognizer` 的 `bounds is None` 分支（3 字名后接 CJK 时跳过）。
- 地名走 `_re_known` + `_re_generic` 启发式（无 jieba ns 分支）。
- 机构走 `elif not _next_ok(...)` 右边界分支（无 bounds 分支）。
- 职务走 `elif` 右边界分支。

**等价性 golden**：用 Python 强制 `segmentation._HAS_JIEBA=False` 生成，禁用生产环境的 jieba 精度增益。

**风险披露**：若生产装了 jieba，Python 版精度略高于 Node 版（nr/ns 词性过滤）。此差异为**已知且可接受**——Node 版仍满足全部回归用例（这些用例在双模式下均通过）。报告交付时明确记录该口径。

## 3. 模块映射（Python → Node）

| Python 模块 | Node 文件 | 要点 |
| --- | --- | --- |
| `server.py` | `node_pii/server.mjs` | stdio JSON 行协议；`_mask_value` / `_restore_display` 逐字复刻 |
| `normalize.py` | `node_pii/normalize.mjs` | NFKC 单字符折叠 + 分隔符吞噬 + `_trailing_is_complete_mobile` + 坐标映射 |
| `chinese_recognizers.py` | `node_pii/recognizers.mjs` | 15 个识别器 + 词表加载（assets 3 文件）+ id/luhn 校验 + 全部正则常量 |
| `custom_rules.py` | `node_pii/custom_rules.mjs` | JSON 正则规则 + hints + 优先级 + 热更新；**Python 代码规则不支持**（见 §6） |
| `engine.py` | `node_pii/engine.mjs` | 分析流水线 + `_resolve_overlaps` + `redact` + `restore` |
| `db.py` | `node_pii/db.mjs` | `node:sqlite` 复用 schema；WAL/NORMAL；`get_max_seq` 同口径 |
| `hooks.py` | `node_pii/hooks.mjs` | 配置优先级 + `session_id` sha1 + HMAC journal（node:crypto）+ 预设热更新 |
| `journal.py` | `node_pii/journal.mjs` | JSONL + 轮转 |
| — | `tests/node/engine-equivalence.mjs` | Python golden 对齐 Node 输出 |

## 4. 关键语义清单（逐项对齐）

- 占位符 `⟦PII:<TYPE>:<SEQ:04d>⟧`，`SEQ` 跨调用全局递增（按 session+type，`get_max_seq`）。
- `_PRIO` 优先级表 13 项（见 engine.py:39-42），自定义类型兜底 99。
- 重叠消解：先比长度（长优先），等长比优先级，再比起点；贪心不重叠；末尾按 start 排序。
- 白名单：`_drop_protected` 区间相交 `r.start < e && r.end > s`。
- UUID：整体跳过（落在 UUID span 内的实体丢弃）。
- entity_types：空集合 = 全开；未知类型告警忽略；全无效归空 = 全开（fail toward 多脱敏）。
- 自定义规则类型始终保留（不被内置勾选列表关掉）。
- 归一化：分隔符集合（空格/Tab/CR/LF/不换行/全角/窄空格/零宽/连字符系列/ASCII hyphen/underscore，**不含点号**）；仅夹在两数字间且单字符才吞；完整 11 位手机号右侧禁吞。
- `_mask_value`：邮箱 local 首字符+`***`@domain；len≤4 首字符+`*`×(n-1)；否则前2+`*`×(n-4)+后2。
- server redact 只下发**增量**新占位符 map（diff `before_keys`）。
- `restore` 只替换文本中实际出现的占位符，去重。

## 5. 配置与环境变量（保持兼容）

- `PII_GUARD_REPO` / bundle config.repo：仓库根（server.mjs 定位词表与 db）。
- `PII_DSH_DB_PATH`：SQLite 路径（默认 `<repo>/.pii_presidio_store/sessions.db`）。
- `PII_DSH_PRESET` / preset.json：entity_types / whitelist_path / custom_rules_path。
- `PII_DSH_ENTITY_TYPES`、`PII_DSH_WHITELIST`、`PII_DSH_CUSTOM_RULES`：env 覆盖。
- `PII_DSH_LOG_HMAC_KEY`：HMAC 密钥；否则 `<db同目录>/journal_hmac.key`（随机生成 + 权限收紧）。
- `PII_GUARD_DISPLAY` / `PII_GUARD_FAIL_OPEN` / shell 相关：由 guard 插件（Node）处理，不在 server 层。

## 6. 已知不支持 / 差异

- **Python 代码规则（.py analyze()）**：Node 无法等价执行任意 Python。迁移后 `PII_DSH_CUSTOM_RULES` 中的 `.py` 规则忽略并告警；JSON 正则规则完整支持。若实际使用 .py 规则，需人工转写为 JSON（报告列出检查结论）。
- **jieba 精度增益**：见 §2。
- **CLI Office 二进制文档**（docx/xlsx/pptx）：`documents.py` 依赖 python-docx/pptx/openpyxl，与 guard server 运行时无关，**不在本次迁移范围**（这些是独立 CLI 功能，保留 Python 脚本，不影响 guard 零 Python 目标）。

## 7. 验收标准

1. `tests/node/engine-equivalence.mjs`：≥30 组成对样本（正常/变体/边界/精度）Python golden 与 Node 输出（redacted 文本 + map + n）逐字一致。
2. `presidio_pii/server.py` 与 `node_pii/server.mjs` 同协议：用同一组请求分别喂两个进程，响应结构一致。
3. guard 插件 `spawn` 指向 Node server，三套 JS 烟测（plugin_terms / plugin_display / plugin_jobs）全绿。
4. `install.ps1` 不再要求 Python 版本校验；仅 dsh+node 环境可完成离线安装。
5. 全量 pytest 保持绿（Python 引擎保留，不删除——等价性基准与 CLI 仍需）。
6. 报告落盘（CODE-REVIEW 或新迁移报告），披露 §6 差异。

## 8. 实施顺序

1. 契约文档（本文件）✅
2. 并行实现：核心引擎组（normalize/recognizers/engine）+ 基础设施组（db/journal/hooks/server）
3. guard 改 spawn + install.ps1 去 Python
4. 生成 Python golden，写等价性测试
5. 全量验证 + 报告落盘
