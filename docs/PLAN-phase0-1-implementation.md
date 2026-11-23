# PII Guard Phase 0/1 实施计划（已收口）

来源：docs/PLAN-pii-research-implementation.md 与 RESEARCH-pii-protection.md §6。
计划执行日期：2026-11-20；收口日期：2026-11-20。
范围：Phase 0 字段/F-04~F-07、Phase 1 最小 PII 预设、四件套、门禁与 MCP 收窄。
Python/Node 双端 parity 是硬约束。

## 状态

### Phase 0 —— 字段补齐与边界修复（全部完成）

- [x] 0.1 字段红测试：`tests/test_extended_fields.py`，9 正样本 + 6 负样本 + F-04~F-07。
- [x] 0.2 规则库：`rule_libraries/extended-fields.json`，7 个 kind:regex JSON 规则，公共正则子集。
- [x] 0.3 Python：扩展 F-04（职务标签边界人名）/F-05（完整门牌）/F-06（机构代词左边界）/F-07（籍贯省+市）。
- [x] 0.4 Node：同步 `node_pii/recognizers.mjs` 与 `node_pii/custom_rules.mjs`（paths 别名/导出 loadJsonRules）。
- [x] 0.5 对拍：extended parity 12 正样本/6 负样本逐实体一致。
- [x] 0.6 将临时 parity smoke 固化并接入全量测试：`tests/node/extended-fields.mjs`。
- [x] 0.2'（补做）预设实体清单扩到 20 类：`plugins/dsh-presidio-pii/lib/terms.js` 的
      `PRESET_DEFAULT_ENTITY_TYPES` 与 `.agent-presets/presidio-pii/preset.json` 同步加入
      AGE / BIRTH_DATE / GENDER / ETHNICITY / EDUCATION / IM_ACCOUNT / EMPLOYEE_ID。
- [x] 0.8（2026-11-20 补做）golden 扩到 57 条并接入扩展规则库：
      `tools/gen_equivalence_golden.py` 传 `custom_rules=rule_libraries/extended-fields.json`，
      新增 F-04/F-05/F-06/F-07 与 7 类字段正样本 + 4 条扩展负样本；
      `tests/node/engine-equivalence.mjs` 同步传 `customRules`，双端加载同一份规则库才可比。
- [x] 0.9（2026-11-20 补做）门禁 #1 从「PERSON 硬编码」升级为逐类断言：
      `tools/release_gate.py` 新增 `ENTITY_PROBES`（20 类探针）+ `_check_entity_coverage()`，
      按 preset 声明的类型逐类要求命中，**声明了却没命中或没配探针一律 FAIL**（差集不允许静默通过）。

### Phase 1 —— 最小 PII 预设与四件套（全部完成）

- [x] 1.1 重写最小 PII 预设，只挂四件套：`agent.cordis.yml` 与 `bundle/cordis.patch.yml`
      移除 tool-bash / tool-pwsh / tool-fs / tool-fs-search / tool-todo / tool-web，
      新增 `pii-guard-fs` 行。home 层 `$DSH_HOME/cordis.patch.yml` 的
      preset-presidio-pii 生效定义同步收窄（并补齐 `pii-guard.config.repo`，
      修掉部署态「无法确定仓库根」告警）。
- [x] 1.2 `read_redacted/write_raw/restore/ls` 落地：`plugins/dsh-presidio-pii/lib/fs.mjs`，
      D3 抹 displayPath（返回值与错误消息都只留 basename），自限长
      （读 200k / 写 500k / ls 500 条）防止绕开 guard 触发 spill。
- [x] 1.3 门禁三条：`tools/check_phase1_gates.mjs`（①②③）+ 接入 `tools/release_gate.py` 第 13 项。
- [x] 1.4 home 层 `mcp-codebuddy` 置 `disabled: true`（mcp-playwright 早前已从 home 移除），
      Cordis 实际生效定义核对通过（`tools/verify_preset_plugins.mjs` PASS）。
- [x] 1.5 字段探针、五套 JS 回归、全量 pytest、install/verify 全部执行（见证据）。
- [x] 1.6 实施报告与证据落盘：docs/PHASE1-REPORT.md。
- [x] 1.7（追加，2026-11-20 生产接线事故）真实启动暴露 4 项组合缺陷并修复：
      hooks 合并内置规则库（rule_libraries/*.json + 用户词表）、Python
      `_known_entity_types` 并入 `_PRIO`、双端 analyze 拆 raw/probe 两桶（wants_raw
      原文坐标不再被 `norm.back()` 平移）、guard 加载期静默解析。新增门禁 #14
      （双端 hooks 生产路径）与 `tests/node/preset-runtime-types.mjs`。详见
      [INCIDENT-20261120-runtime-wiring.md](INCIDENT-20261120-runtime-wiring.md)。

## 最终证据

| 验证项 | 命令 | 结果 |
| --- | --- | --- |
| Python 全量 | `python -m pytest tests/ -q` | 279 passed, 8 subtests passed |
| 字段专项 | `python -m pytest tests/test_extended_fields.py` | 19 passed |
| Node 引擎等价 | `node tests/node/engine-equivalence.mjs` | 57/57 ALL_GOLDEN_MATCH（含 7 类扩展字段） |
| Node 协议 | `node tests/node/protocol-smoke.mjs` | 3/3 ALL_PROTOCOL_CHECKS_PASS |
| Node 字段 parity | `node tests/node/extended-fields.mjs` | NODE_EXTENDED_FIELDS_PASS 12 |
| 四件套回归 | `node tests/node/guard-fs-tools.mjs` | 33 passed, 0 failed |
| UI 词表插件 | `node tests/js/plugin_terms.mjs` | 75 passed, 0 failed |
| guard 任务烟测 | `node tests/js/plugin_jobs.mjs <guard>` | ALL PASS |
| guard 显示烟测 | `node tests/js/plugin_display.mjs <guard>` | ALL PASS（含 S3 config.repo） |
| 门禁①②③ | `node tools/check_phase1_gates.mjs` | GATE_PHASE1_DONE，exit 0 |
| 门禁第 13 项 | `python tools/release_gate.py --only 13` | PASS |
| 门禁第 1 项（逐类） | `python tools/release_gate.py --only 1` | PASS，逐类探针 20/20 命中 |
| 门禁第 1 项反证 | 伪造 `NONEXISTENT_TYPE` / 新增无探针类型 | 两种都 FAIL（缺口不会被放过） |
| 预设插件解析 | `node tools/verify_preset_plugins.mjs` | PASS（home 18 / bundle 18） |
| 安装自检 | `pwsh tools/verify_install.ps1` | PASS=4 FAIL=0 SKIP=1，exit 0 |
| 生产接线（Node） | `node tests/node/preset-runtime-types.mjs` | PRESET_RUNTIME_TYPES_PASS 8 项 |
| 生产接线（Python） | `python tools/check_runtime_types.py` | ok=true, declared=20, missing=[] |
| 门禁第 14 项 | `python tools/release_gate.py --only 14` | PASS（node=ok py=ok） |
| 全量 pytest（事故修复后） | `python -m pytest tests/ -q` | 281 passed, 8 subtests passed |

## 已知边界（如实披露，非缺陷逃避）

1. **F-06 语义收窄**：「他是公司总经理」不再产出 ORGANIZATION（只留 JOB_TITLE 总经理）。
   这比旧实现准确，但属策略收紧；依赖「短主体公司也算机构」的旧用例需要改断言。
2. **spill 治理只做到工具侧**：宿主 spill-local / spill-policy / session-persistence
   预设管不到，四件套靠自限长 + 不回 locator 兜住；超长内容仍会被截断。
3. **mcp-211dec4477（playwright）保留**：由设置卡片管理开关，不在本仓库 patch 内覆盖。

## 门禁口径修正（2026-11-20 复审，均属"门禁本身有缺陷"而非放水）

| 项 | 旧口径问题 | 新口径 |
| --- | --- | --- |
| #5 格式覆盖面 | 断言字面量 `svc.on("error"`，B1 竞态修复把 `svc` 改成句柄对象后合法代码被判回归 | 改为正则断言 `\.on\(\s*["']error["']`（**行为**：子进程挂 error 处理），不再锁变量名 |
| #7 密钥扫描 | 扫描器自带的假凭据夹具（`tests/test_release_gate_rules.py`）永久污染历史与工作树判定 | 按路径豁免并**每次披露条数** `selftest_fixtures_exempted=N`，其余路径零容忍；命中的是 AWS 官方文档示例 key（`AKIA` 前缀 + `EXAMPLE` 后缀）一类假值 |
| #10 源码可溯源 | `commit == HEAD` 使「提交清单」这个动作本身导致失配，形成死循环 | 允许清单绑定提交是 HEAD 的**祖先**；绑定强度由 `source_tree_sha256`（覆盖 wheel 打包源码）承担 |

反证：三项修正后重新跑全量门禁，PASS 10 → PASS 12（#10 需按发布流程重建产物后 PASS，见 RELEASE-RUNBOOK）。
