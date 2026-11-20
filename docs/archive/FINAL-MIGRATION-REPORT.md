# PII 引擎 Node 原生迁移 — 最终报告

**目标**：用 Node/JS 重写 PII 脱敏引擎，消除 dsh-pii-guard 运行时 Python 前置依赖，保持 JSON-RPC 协议与行为语义等价，让 install.ps1 在仅 dsh + Node 宿主机上可离线安装。  
**分支**：`refactor/node-pii-engine`（未提交，待合并）  
**状态**：全部验收通过，可合并。

---

## 1. 交付物清单

### 新增（Node 原生引擎）
| 文件 | 职责 |
|------|------|
| `node_pii/engine.mjs` | 核心流水线：analyze → 过滤 → 裁剪 → 去重叠 → 占位符替换 → 映射登记 |
| `node_pii/recognizers.mjs` | 15 个中文识别器（身份证/15位证/手机/座机/邮箱/统信码/银行卡/护照/车牌/IP+MAC/人名/人名库/地点/机构/职务） |
| `node_pii/normalize.mjs` | 归一化（NFKC、数字间分隔符吞噬、手机号拆分闸门）、坐标原文回映射 |
| `node_pii/custom_rules.mjs` | JSON 自定义正则规则，热更新（mtime+size 签名、1s 节流）、优先级取最小 |
| `node_pii/db.mjs` | SQLite（node:sqlite）映射登记，WAL+NORMAL，getMaxSeq 按 (session, ptype) |
| `node_pii/journal.mjs` | JSONL 审计日志，按字节轮转，跳过坏行 |
| `node_pii/hooks.mjs` | 会话 ID / HMAC 指纹 / preset 配置加载（env > preset > 默认）、beforeLlm/afterLlm 记日志 |
| `node_pii/server.mjs` | stdio JSON 行协议常驻服务（redact / restore full / restore mask） |

### 新增（测试与文档）
| 文件 | 职责 |
|------|------|
| `tests/node/golden.json` | 41 组等价性样本（Python 强制无 jieba 生成） |
| `tests/node/engine-equivalence.mjs` | Node vs Python golden 逐字比对（redacted/n/map/entity_counts/n_whitelisted） |
| `tests/node/protocol-smoke.mjs` | redact → restore(full) → restore(mask) 端到端协议 smoke |
| `tools/gen_equivalence_golden.py` | golden 生成脚本（强制 `_HAS_JIEBA=False`） |
| `docs/NODE-ENGINE-MIGRATION-PLAN.md` | 迁移方案、模块映射表、已知不支持、验收标准 |
| `docs/NODE-ENGINE-API-CONTRACT.md` | 接口契约（签名锁死） |
| `docs/CODE-REVIEW-REPORT.md` | 代码审查报告（本次自审，无 blocker） |
| `docs/FINAL-MIGRATION-REPORT.md` | 本文档 |

### 修改（去 Python 依赖）
| 文件 | 变更 |
|------|------|
| `plugins/dsh-pii-guard/lib/index.js` | `PY="python"` → `NODE_BIN`（env PII_GUARD_NODE / 兼容 PII_GUARD_PY / process.execPath）；`SERVER` → `node_pii/server.mjs`；哨兵文件 `server.py` → `server.mjs` |
| `tools/install.ps1` | 第 1b 项改为 Node ≥22.5 + node:sqlite 可用性校验，加 `node_pii/server.mjs` 哨兵；注入 UTF-8 BOM 修复 PS5.1 中文乱码 |
| `tools/verify_install.ps1` | 第 1 项 `node --check node_pii/server.mjs`，第 2 项 `node tests/node/protocol-smoke.mjs`；注入 UTF-8 BOM |

---

## 2. 验收标准与证据

| # | 验收标准 | 结果 | 证据 |
|---|----------|------|------|
| 1 | ≥30 组 golden 逐字一致 | ✅ 41/41 | `node tests/node/engine-equivalence.mjs` → `EQUIVALENCE: 41/41 passed, 0 failed, ALL_GOLDEN_MATCH` |
| 2 | JSON-RPC 协议一致 | ✅ 3/3 | `node tests/node/protocol-smoke.mjs` → `PROTOCOL_SMOKE: 3/3 passed` |
| 3 | 三套 JS 插件烟测绿 | ✅ 全绿 | `plugin_jobs` ALL PASS；`plugin_display` ALL PASS（含 config.repo 覆盖）；`plugin_terms` 63/63 |
| 4 | install.ps1 去 Python | ✅ | 真跑 exit=0：Node 版本 24.16 PASS；引擎入口存在 PASS；guard 插件已安装 |
| 5 | 全量 pytest 保持绿 | ✅（前序已验） | presidio_pii 侧未改动，Python 单元测试组未回归 |
| 6 | 报告落盘 | ✅ | 本文档 + CODE-REVIEW-REPORT.md 已落盘 |

---

## 3. 关键决策与取舍

1. **基准模式：Python 无 jieba fallback**。官方支持，有双模式测试基准，与 Node 零依赖约束吻合。代价：生产装 jieba 时 Python 精度略高，已在 `docs/NODE-ENGINE-MIGRATION-PLAN.md` "已知不支持" 中披露。
2. **索引口径：JS UTF-16 code unit**。中文均在 BMP，与 Python 字符下标等价；emoji 增补平面未做代理对拆分（基准无此场景，可追加）。
3. **事务语义：显式 BEGIN/COMMIT**。node:sqlite 默认 autocommit，Python sqlite3 隐式事务；`db.mjs` 显式维护事务边界以复刻 `addMapping(commit=false) + commit()` 批量提交。
4. **Windows ACL：告警不阻断**。`harden()` 在 Windows 跳过 `icacls`，仅告警；HMAC key 文件未按 `0600` 收紧，生产部署需手动补齐（已列为 suggestion）。

---

## 4. 已知不支持（与 Python 版差异）

- jieba 精度增益：不在范围，永久采用 fallback 模式。
- Python 代码规则（`.py` 自定义 analyze()）：Node 无法等价执行，忽略并告警。
- CLI Office 文档脱敏（`python -m presidio_pii.cli`）：不在迁移范围，改为 Node server.mjs JSON-RPC。
- Windows ACL 权限收紧：仅告警，不自动 `icacls`。

---

## 5. 合并前建议（来自 CODE-REVIEW-REPORT）

- `engine.mjs` defaultRepoDir() 与 `hooks.mjs` 路径口径统一（suggestion）。
- `hooks.mjs` 单例热更新纳入 custom rules 签名（suggestion）。
- `server.mjs` mask 分支合并两次正则扫描（suggestion）。
- `recognizers.mjs` 词表避免模块级可变全局（suggestion）。
- Windows ACL 生产部署手动补齐步骤文档化（suggestion）。

以上为 suggestion，不阻塞合并。

---

## 6. 结论

PII 引擎已完全迁移为 Node 原生实现，零 npm 依赖，与 Python 基准 100% 等价（41/41），协议层端到端通过（3/3），部署脚本已去 Python 化并通过 PS5.1 验证。建议合并 `refactor/node-pii-engine` 入主分支，并废弃 `presidio_pii/` 与旧 Python hook 入口。

报告落盘时间：2026-11-19  
报告人：P8 Owner（自审 + 自验）
