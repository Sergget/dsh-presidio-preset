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
- [x] 0.2'（补做）预设实体清单扩到 20 类：`plugins/dsh-pii-guard-terms/lib/index.js` 的
      `PRESET_DEFAULT_ENTITY_TYPES` 与 `.agent-presets/presidio-pii/preset.json` 同步加入
      AGE / BIRTH_DATE / GENDER / ETHNICITY / EDUCATION / IM_ACCOUNT / EMPLOYEE_ID。

### Phase 1 —— 最小 PII 预设与四件套（全部完成）

- [x] 1.1 重写最小 PII 预设，只挂四件套：`agent.cordis.yml` 与 `bundle/cordis.patch.yml`
      移除 tool-bash / tool-pwsh / tool-fs / tool-fs-search / tool-todo / tool-web，
      新增 `pii-guard-fs` 行。home 层 `E:/Code/dsh_home/cordis.patch.yml` 的
      preset-presidio-pii 生效定义同步收窄（并补齐 `pii-guard.config.repo`，
      修掉部署态「无法确定仓库根」告警）。
- [x] 1.2 `read_redacted/write_raw/restore/ls` 落地：`plugins/dsh-pii-guard-fs/lib/index.mjs`，
      D3 抹 displayPath（返回值与错误消息都只留 basename），自限长
      （读 200k / 写 500k / ls 500 条）防止绕开 guard 触发 spill。
- [x] 1.3 门禁三条：`tools/check_phase1_gates.mjs`（①②③）+ 接入 `tools/release_gate.py` 第 13 项。
- [x] 1.4 home 层 `mcp-codebuddy` 置 `disabled: true`（mcp-playwright 早前已从 home 移除），
      Cordis 实际生效定义核对通过（`tools/verify_preset_plugins.mjs` PASS）。
- [x] 1.5 字段探针、五套 JS 回归、全量 pytest、install/verify 全部执行（见证据）。
- [x] 1.6 实施报告与证据落盘：docs/PHASE1-REPORT.md。

## 最终证据

| 验证项 | 命令 | 结果 |
| --- | --- | --- |
| Python 全量 | `python -m pytest tests/ -q` | 279 passed, 8 subtests passed |
| 字段专项 | `python -m pytest tests/test_extended_fields.py` | 19 passed |
| Node 引擎等价 | `node tests/node/engine-equivalence.mjs` | 41/41 ALL_GOLDEN_MATCH |
| Node 协议 | `node tests/node/protocol-smoke.mjs` | 3/3 ALL_PROTOCOL_CHECKS_PASS |
| Node 字段 parity | `node tests/node/extended-fields.mjs` | NODE_EXTENDED_FIELDS_PASS 12 |
| 四件套回归 | `node tests/node/guard-fs-tools.mjs` | 33 passed, 0 failed |
| UI 词表插件 | `node tests/js/plugin_terms.mjs` | 75 passed, 0 failed |
| guard 任务烟测 | `node tests/js/plugin_jobs.mjs <guard>` | ALL PASS |
| guard 显示烟测 | `node tests/js/plugin_display.mjs <guard>` | ALL PASS（含 S3 config.repo） |
| 门禁①②③ | `node tools/check_phase1_gates.mjs` | GATE_PHASE1_DONE，exit 0 |
| 门禁第 13 项 | `python tools/release_gate.py --only 13` | PASS |
| 预设插件解析 | `node tools/verify_preset_plugins.mjs` | PASS（home 18 / bundle 18） |
| 安装自检 | `pwsh tools/verify_install.ps1` | PASS=4 FAIL=0 SKIP=1，exit 0 |

## 已知边界（如实披露，非缺陷逃避）

1. **F-06 语义收窄**：「他是公司总经理」不再产出 ORGANIZATION（只留 JOB_TITLE 总经理）。
   这比旧实现准确，但属策略收紧；依赖「短主体公司也算机构」的旧用例需要改断言。
2. **spill 治理只做到工具侧**：宿主 spill-local / spill-policy / session-persistence
   预设管不到，四件套靠自限长 + 不回 locator 兜住；超长内容仍会被截断。
3. **Phase 0.8 / 0.9 未做**（golden 扩 7 字段样本、门禁 #1 扩新字段断言）：
   属 PLAN-pii-research-implementation 的 Phase 0 余项，不在本轮批准范围，已留在该计划中。
4. **mcp-211dec4477（playwright）保留**：由设置卡片管理开关，不在本仓库 patch 内覆盖。
