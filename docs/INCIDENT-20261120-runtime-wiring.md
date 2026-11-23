# 生产接线修复报告（2026-11-20 启动报错闭环）

## 事故输入

用户重启 DSH 后报两条错：

1. `[pii-guard] 无法确定仓库根：…`（每次启动必现）
2. `[pii] 忽略未知实体类型 ["AGE","BIRTH_DATE","EDUCATION","EMPLOYEE_ID","ETHNICITY","GENDER","IM_ACCOUNT"]`

## 根因与修复

### 根因一：guard 加载期误报「无法确定仓库根」

`plugins/dsh-presidio-pii/lib/guard.js:96` 在**模块加载期**就调用 `resolveRepo(null)`——
此时还没有 bundle config，部署态（插件在 DSH_HOME）`DEFAULT_REPO` 推断必为空，
于是每次启动都刷一条假告警。`apply()` 拿到 `config.repo` 后才是真值。

**修复**：拆出 `resolveRepoQuiet(config)`（静默解析），模块加载期用它；
带告警的 `resolveRepo(config)` 保留给 `apply → configurePaths`（配置后仍解析不到才真告警）。

### 根因二：内置规则库从未进生产链路（R-43 同类事故）

golden / 门禁 #1 全绿，但生产报「未知实体类型」。因为**测试在代码里显式传了
`customRules`，而生产走 preset + hooks，hooks 只读 `custom_rules_path`（用户词表），
`rule_libraries/extended-fields.json` 从未加载** —— 断言了一套生产不用的配置。

**修复（双端 parity）**：
- `presidio_pii/hooks.py` `_custom_rules_spec()`：`rule_libraries/*.json`（排序后）
  + 用户规则，分号拼接（CustomRuleSet 双端都支持 `[;,]` 多路径 + 逐文件热更新签名）。
- `node_pii/hooks.mjs` `customRulesSpec()`：同逻辑（`builtinRuleLibraries()` 枚举 + 合并）。

### 根因三（修复二途中暴露）：Python `_known_entity_types` 漏了 `_PRIO` 键

`MAC_ADDRESS` 由 IpMac 识别器动态产出，不在识别器静态 `entity_type` 属性里 → 被
判「未知」从白名单剔除。Node 端一直是 `内置 ∪ PRIO ∪ 自定义` 口径。
**修复**：`engine.py:73` 并入 `set(_PRIO)`，与 Node 对齐。

### 根因四（生产样本复验暴露）：wants_raw 结果被二次坐标平移（双端同错）

生产路径实测发现脱敏结果整体右移一字（「男」挪成「民」、「1990-03-07」吞掉
尾字符、账号前两位 `zh` 留明文）。根因：`analyze()` 里 wants_raw（自定义规则，
原文坐标）与归一化识别器的结果**混在同一个列表**里过了 `norm.back()` 映射——
原文坐标被当归一化坐标平移。golden 57/57 逐字一致却都错，因为**两端犯了同一
个错**（等价性测试测不出单侧正确性）。

**修复（双端 parity）**：`engine.py analyze()` / `engine.mjs analyze()` 拆成
`raw_results` 与 `results` 两个桶，只对归一化桶做 `back()` 映射，最后合并。

## 防回归

- 新测试 `tests/node/preset-runtime-types.mjs`：**只走生产路径**
  （`PII_DSH_PRESET` → `hooks.getEngine()` → redact），8 项断言：
  20 类全已知 / 内置库在 sources / 7 类规则在场 / redact 真产出 / 无告警 /
  值真被替换 / restore 无损。
- `tests/test_extended_fields.py` 追加两条 Python 同口径测试。
- 新门禁 **#14 生产配置实体类型接线（双端 hooks）**：`tools/release_gate.py
  check_runtime_wiring()` 跑上述 Node 测试 + `tools/check_runtime_types.py`（Python
  hooks 路径，JSON 证据输出）。`--only 14` PASS。
- 既有 `test_hooks_reload_rules` 的 `reload_rules()==1` 断言更新为 `>=1`
  （内置库常驻参与计数），并加断言「只配用户规则时扩展字段仍生效」。

## 部署同步

`<DSH_HOME>/profiles/desktop/node_modules/dsh-presidio-pii/lib/guard.js` 已同步
（sha256 与仓库一致：AD147B46…07F31）。

## 验证证据（全绿）

| 套件 | 结果 |
| --- | --- |
| pytest 全量 | 281 passed, 8 subtests |
| engine-equivalence | 57/57 ALL_GOLDEN_MATCH |
| preset-runtime-types（新） | 8/8 PASS |
| extended-fields.mjs | PASS 12 |
| protocol-smoke | 3/3 |
| guard-fs-tools | 33 passed |
| plugin_terms / jobs / display | 75 / ALL / ALL |
| 门禁 #13 / #14 | GATE_PHASE1_DONE / PASS |
| 生产路径 server 实测 | 8 实体，跨度逐项对齐原文，无明文残留 |

## 涉改文件

- `plugins/dsh-presidio-pii/lib/guard.js`（加载期静默解析）
- `presidio_pii/hooks.py`、`node_pii/hooks.mjs`（内置规则库合并）
- `presidio_pii/engine.py`、`node_pii/engine.mjs`（_known_entity_types 并 PRIO；
  wants_raw 坐标不再被平移）
- `tools/release_gate.py`（门禁 #14）、`tools/check_runtime_types.py`（新）
- `tests/node/preset-runtime-types.mjs`（新）、`tests/test_extended_fields.py`、
  `tests/test_custom_rules.py`

## 遗留

- `docs/RELEASE-GATE.md` 与 `docs/PLAN-phase0-1-implementation.md` 需补记 #14 与本次事故条目（随提交一起做）。
- 用户需再重启一次 DSH 验证两条报错消失。
