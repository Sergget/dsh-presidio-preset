# Phase 1 实施报告：最小 PII 预设与四件套

日期：2026-11-20　分支：`refactor/node-pii-engine`
上游依据：`docs/RESEARCH-pii-protection.md` §6 Phase 1、§8 验收契约；`docs/PLAN-pii-research-implementation.md` 1.1–1.4
决策前提：D1（删 shell / 收窄工具面）、D3（自建工具抹显示路径）已由用户拍板执行。

---

## 1. 做了什么

### 1.1 工具面收窄（直读通道 4 → 1）

| 项 | 改动前 | 改动后 |
| --- | --- | --- |
| shell | `tool-bash`（非 Windows）/ `tool-pwsh`（Windows） | **不挂载** |
| 文件读写 | `tool-fs`（read / write / edit / apply_patch） | **不挂载** |
| 检索 | `tool-fs-search`（glob / grep） | **不挂载** |
| 待办 / 联网 | `tool-todo` / `tool-web` | **不挂载** |
| 文件面 | — | `pii-guard-fs` 四件套：`read_redacted` / `write_raw` / `restore` / `ls` |
| MCP 直读 | `mcp-codebuddy`（可自由读写磁盘） | `disabled: true` |

落点三处，互相一致：

- `.agent-presets/presidio-pii/agent.cordis.yml`（仓库侧预设模板）
- `.agent-presets/presidio-pii/bundle/cordis.patch.yml`（安装用 bundle 模板）
- `$DSH_HOME/cordis.patch.yml` 的 `preset-presidio-pii` **实际生效定义**
  （当时已备份为 `cordis.patch.yml.bak-phase1-20261120-133810`）

顺带修掉一个真实缺陷：home 层 `pii-guard` 行原先没有 `config.repo`，部署在
`DSH_HOME` 时从模块路径推断仓库根必然失败，启动即打
`[pii-guard] 无法确定仓库根` 并回落。当时以显式 `config.repo` 兜住。

> **后续变更（统一 bundle 之后）**：home 层的内联 `preset-presidio-pii` 已被删除，
> 改为由单一 bundle `dsh-presidio-pii` 自带的 `cordis.patch.yml` 提供；
> 路径不再需要 `config.repo` 指定，改由 `lib/paths.mjs` 按
> `config.dataDir` → `PII_GUARD_DATA_DIR` → `config.repo` / `PII_GUARD_REPO` →
> `$DSH_HOME/data/presidio-pii` 的优先级解析。

### 1.2 四件套插件

`plugins/dsh-presidio-pii/lib/fs.mjs`（零 DSH 包依赖，与既有插件同风格）：

- `read_redacted`：读文件 → 交给 PII 引擎 → 返回**占位符文本**（原文不出模型侧）
- `write_raw`：把 `restore` 还原后的原文落盘
- `restore`：占位符 → 原文，只在最终交付时用
- `ls`：目录条目（仅文件名）

D3 实现：`sanitizePath()` 只保留 basename；错误消息里的路径片段也过 `stripDirs()`
压成 basename；`restore` 与所有错误统一 `displayPath: "<redacted>"`。

自限长（防绕开 guard 触发宿主 spill）：读 200 000 字符、写 500 000 字符、ls 500 条，
超限返回 `truncated: true`，**永不返回 spill locator**。

fail-closed：引擎拿不到时 `setRedact` 直接抛错，工具返回 error —— 绝不直通原文。

### 1.3 门禁

`tools/check_phase1_gates.mjs`：

| 门禁 | 断言 | 扫描范围 |
| --- | --- | --- |
| ① | 不得出现 `dsh-tool-executor-ptc` | `agent.cordis.yml` + `bundle/cordis.patch.yml` |
| ② | 不得出现 `PII_GUARD_FAIL_OPEN=1` | 同上 |
| ③ | spill 目录内无嵌套占位符 `⟦PII:⟦PII:`、无 ≥6 位未脱敏数字串 | `.pii_presidio_store/spill{,-local}` |

并接入 `tools/release_gate.py` 第 13 项（额外静态断言：预设不得再挂
`dsh-tool-bash/pwsh/fs/fs-search/todo/web`，且必须挂 `dsh-presidio-pii/fs`）。

### 1.4 安装链

（当时）`tools/install.ps1` 增加第 3b 步：把 `plugins/dsh-presidio-pii/lib/fs.mjs`
复制到 `$DSH_HOME/plugins/dsh-presidio-pii/lib/fs.mjs`，与 guard 插件同样处理；
bundle patch 里的仓库根与 DSH_HOME 占位符由安装脚本渲染，渲染后残留占位符直接 Fail。

> **后续变更（统一 bundle 之后）**：散装复制与占位符渲染都已废弃。`tools/install.ps1`
> 现在只做完整性校验 + 遗留残留排查，安装走 DSH 官方 bundle 机制
> （`plugin_manager install_bundle` / `dsh plugin --profile <name> add <bundleDir>`）。
> 插件自身通过 `lib/paths.mjs` 从 `import.meta.url` 推导包根，运行期数据目录按
> `config.dataDir` → `PII_GUARD_DATA_DIR` → `config.repo` / `PII_GUARD_REPO` →
> `$DSH_HOME/data/presidio-pii` 解析，不需要任何渲染步骤。

---

## 2. 验证证据（全绿）

| 验证项 | 命令 | 结果 |
| --- | --- | --- |
| Python 全量 | `python -m pytest tests/ -q` | **279 passed, 8 subtests** |
| 字段专项 | `python -m pytest tests/test_extended_fields.py` | 19 passed |
| Node 引擎等价 | `node tests/node/engine-equivalence.mjs` | **41/41 ALL_GOLDEN_MATCH** |
| Node 协议 | `node tests/node/protocol-smoke.mjs` | **3/3 ALL_PROTOCOL_CHECKS_PASS** |
| Node 字段 parity | `node tests/node/extended-fields.mjs` | NODE_EXTENDED_FIELDS_PASS 12 |
| 四件套回归 | `node tests/node/guard-fs-tools.mjs` | **33 passed, 0 failed** |
| 词表 UI 插件 | `node tests/js/plugin_terms.mjs` | 75 passed, 0 failed |
| guard 任务烟测 | `node tests/js/plugin_jobs.mjs plugins/dsh-presidio-pii/lib/guard.js` | ALL PASS |
| guard 显示烟测 | `node tests/js/plugin_display.mjs plugins/dsh-presidio-pii/lib/guard.js` | ALL PASS |
| 门禁①②③ | `node tools/check_phase1_gates.mjs` | GATE_PHASE1_DONE（exit 0） |
| 门禁第 13 项 | `python tools/release_gate.py --only 13` | PASS |
| 预设插件解析 | `node tools/verify_preset_plugins.mjs` | PASS（home 18 / bundle 18） |
| 安装自检 | `pwsh tools/verify_install.ps1` | PASS=4 FAIL=0 SKIP=1（exit 0） |
| YAML 可解析 | `yaml.parse` × 3 文件 | 全部 OK |

四件套回归覆盖点（33 条）：脱敏生效且原文不泄漏、`displayPath` 只留 basename、
错误消息不含绝对目录、超长截断、相对路径解析、非目录报错、`sanitizePath` 兜底、
以及「redact 抛错时绝不返回原文」。

---

## 3. 已知边界与剩余风险

1. **宿主 spill 层面管不到**。`spill-local` / `spill-policy` / `session-persistence`
   属于宿主平面，预设无法声明。四件套用自限长 + 不回 locator 兜住，但代价是
   **超长内容会被截断**（读 200k / 写 500k），不是无损大文件通道。
2. **`write_raw` 会写原文**。这是设计意图（还原后落盘），但意味着模型一旦被诱导
   调用 `write_raw` 就能把原文写到磁盘。防线在"原文从不出现在模型上下文里"——
   `read_redacted` 只返回占位符，`restore` 的结果也不回灌上下文。若将来允许
   模型看到 restore 结果，这条防线就破了，需要重新评估。
3. **`ls` 只抹目录路径，不抹文件名**。文件名本身可能是 PII（例如
   `张三-身份证.pdf`）。当前未做文件名的实体级脱敏，属已知缺口。
4. **home 层改动是环境改动**，不在仓库内。换机器/重装 DSH 后必须重跑
   `tools/install.ps1` 并同步 home patch，否则收窄会失效（guard 仍生效，
   但 shell/直读面会回来）。
5. **MCP `mcp-211dec4477`（playwright）保留**：由设置卡片管理，
   本仓库 patch 不覆盖其 disabled 状态。

---

## 4. 收尾清单

- [x] 三处预设定义一致（仓库模板 / bundle 模板 / home 生效定义）
- [x] 四件套插件实现 + 覆盖测试
- [x] 门禁①②③ 实现并接入 release_gate
- [x] install.ps1 安装四件套
- [x] 全量回归（Python + 五套 JS + 门禁 + install/verify）
- [x] 文档落盘（本报告 + PLAN 收口）
- [ ] 未做：git commit（等确认后提交）
