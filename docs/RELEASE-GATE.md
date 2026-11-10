# 发布门禁清单（v0.1.0）

用途：上线前逐项勾选。每项写明**判定标准**、**当前状态**、**证据位置**。
状态取值：`PASS` / `FAIL` / `SKIP`（无法执行，如离线/待决策）/ `MANUAL`（需人工操作，如重启 DSH）/ `BLOCKED`（等用户决策）/ `PENDING`（未验证）。与 `tools/release_gate.py` 输出一致。

判定原则：宁可标 SKIP/MANUAL/BLOCKED/PENDING，不用"看起来能用"凑 PASS；任何靠降级依赖绕过的项一律记 FAIL。

---

## 0. 总览

| # | 门禁项 | 状态 |
|---|---|---|
| 1 | 读取侧拦截（引擎/插件层） | PASS |
| 2 | 读取侧拦截（DSH 进程内 E2E） | PASS（2026-11-10 重启后 9 步实测，等价口径见 §2） |
| 3 | redact→restore 无损（md + office 三格式） | PASS |
| 4 | 自动 restore 接线（模型回复侧） | PASS（2026-11-10 拍板方案 B 并实现：显示侧还原） |
| 5 | 格式覆盖面 | PASS（文本类 + pwsh 前台 + job_output/job_list） |
| 6 | 依赖漏洞 | PASS |
| 7 | 密钥扫描（工作树 + 历史） | PASS |
| 8 | 单元测试套件 | PASS |
| 9 | 可复现安装（wheel + 干净环境） | PASS |
| 10 | 源码可溯源（origin 含 HEAD / 产物清单） | PASS（A：origin 已含 HEAD，2026-11-10 推送） |
| 11 | 仓库不落真实 PII / 映射库 | PASS |
| 12 | 外部语料（网络下载）回归 | PASS（离线时 SKIP） |

> **最终复核（2026-11-10，正常 PowerShell 窗口）**：`python tools/release_gate.py --json $env:TEMP\release_gate_final.json` → **PASS 12 / FAIL 0 / SKIP 0 / MANUAL 0，退出码 0**（195.3s）。#6 pip-audit 0、#8 160 passed、#9 两次构建字节一致（`77154909…`，58831B）均在正常环境实测通过；此前 DSH 会话内的 3 个 FAIL 确认为沙箱写权限假阴性。**门禁已全部通过，可发布**。证据：正常窗口终端输出（`tools/release_gate.py --json $env:TEMP\release_gate_final.json`）。

---

## 1. 读取侧拦截（引擎/插件层）

- [x] **判定标准**：read/grep 结果中的 PII 被替换为 `⟦PII:TYPE:NNNN⟧`，敏感人名明文不出现；个人类实体计数为 0 时不得误报。
- **当前状态**：PASS
- **证据位置**：
  - 插件实现：`E:/Code/dsh_home/plugins/dsh-pii-guard/lib/index.js`（接缝 `tools/post-execute`，`prepend: true`，失败降级透传并 stderr 告警；`GUARDED_TOOLS = {read, grep}`）
  - 复测（引擎层，detector 修复后重跑）：`paper-01.md` → PERSON 8 / ORGANIZATION 2 / LOCATION 1 / EMAIL_ADDRESS 1，共 12 个占位符，明文人名 absent=true；空白序列与原文完全一致（`whitespace_seq_same=true`，换行/Tab/缩进无损）
  - 计数变化说明：修复前 PERSON 9 / 共 13，多出的 1 条是章节标题「方法」+尾随空格被误判为人名（常用词被尾随空白绕过 `is_common_word` 检查），修复后误报消失，不是漏报；6 篇 paper 语料均同此规律
  - 运行日志：`.pii_presidio_store/hook_log.jsonl`（含 09:56:18 一次 `n_replaced=4` 的成功脱敏记录）。该日志 2026-11-06 起只存元数据（实体类型/数量、内容指纹、`conv_sha1`/`doc_sha1`），不再写原文；存量文件已原地清洗（4,403,418 B → 14,249 B，明文行 65 → 0）

## 2. 读取侧拦截（DSH 进程内 E2E）

- [x] **判定标准**：用户在 DSH 中选 `presidio-pii` 预设，按门禁脚本列出的 9 步（完全退出/重启 + 以下 7 项内容检查）重跑：
  ① read `paper-01.md` 前 8 行含 `⟦PII:PERSON:xxxx⟧` 且无真实人名；
  ② read `normal-01.md` 中 PERSON/ID_NUMBER/PHONE_NUMBER/BANK_CARD 计数全为 0；
  ③ grep `13800138000` 命中行已脱敏；
  ④ pwsh `Get-Content paper-01.md` 输出已脱敏；
  ⑤ pwsh 无 PII 命令（`git status`/`Get-Process`）输出逐字节不变；
  ⑥ pwsh 后台任务 + `job_output` 续读已脱敏；
  ⑦ `job_list` 的命令/描述回显已脱敏。
- **当前状态**：PASS（2026-11-10）—— 用户完成托盘完全退出 + 重启选 `presidio-pii` 预设后，由模型在本会话内用 DSH 内置 read/grep/pwsh/job_* 工具实测步骤 3–9，全部符合；`hook_log.jsonl` 新增 15 条 `before_llm`（n_replaced 与各步骤一一对应，日志仅含元数据无明文）。
- **证据位置**：`.pii_presidio_store/e2e_9steps_2026-11-10.md`（9 步逐条结果与对账）。注意两点：① 步骤 5 为等价口径——`testdata_v2` 文本语料无真实手机号（PHONE_NUMBER 为占位符示例），以"无 PII 行标签命中含 PII 行"验证 grep 拦截；② isError 进程内不易稳定触发，仍由 node 冒烟（门禁 #5）覆盖。执行环境 DSH 0.2.2-rc.1，preset 挂载经 `tools/verify_preset_plugins.mjs` 校验。

## 3. redact→restore 无损

- [x] **判定标准**：还原后的文本单元与源文件**逐字相等**，且残留占位符数 = 0。
  注意：office 容器（zip）的 SHA256 必然变化（时间戳/元数据），**不以容器字节相同作为判据**；md/txt 这类纯文本才要求 SHA256 相同。
- **当前状态**：PASS
- **证据位置**（本轮 pillow 13.0.0 / certifi 2026.10.18 下重跑）：

| 文件 | 单元数 | 单元逐字相等 | 还原占位符 | 残留占位符 |
|---|---|---|---|---|
| `testdata_v2/resume/resume-01.docx` | 27 | True | 13 | 0 |
| `testdata_v2/payroll/payroll-01.xlsx` | 111 | True | 70 | 0 |
| `testdata_v2/report/report-07.pptx` | 19 | True | 13 | 0 |

  - 纯文本：`paper-01.md` redact→restore 后 SHA256 相同（`md_byte_identical=True`）
  - 映射落盘载体：`<产物>.mapping.csv`（`presidio_pii/cli.py` 导出），restore 优先读它，脱敏目录可整体搬运

## 4. 自动 restore 接线（模型回复侧）

- [x] **判定标准**：模型在回复里输出占位符时，用户看到的是原文（或打码值），且还原动作没有把 PII 重新送进模型上下文。
- **当前状态**：PASS（2026-11-10）—— 用户拍板**方案 B**：`agent/assistant-stream` 显示侧改写，附显示设置项。
- **实现**：
  - 插件新增 `agent/assistant-stream` 监听器（`prepend+global`，先于 session-controller 折叠器）：把助手文本流中的占位符同步替换为映射值；跨 chunk 分裂的占位符用「扣尾补头」缓冲（`splitDisplayable`），`end` 帧兜底放行，`start` 帧清缓冲。改写只影响显示流与重连基线——持久化发生在 `live.push()` 内部（早于 emit），**会话存储与模型上下文不受影响**。
  - 设置项 `PII_GUARD_DISPLAY`：`full`（显示完整原值，默认）/ `mask`（部分打码：Python 端 `_mask_value` 完成后仅下发打码值，原文不过 Node）/ `off`（关闭，回到纯占位符）。
  - `server.py` 新增 `op=restore` 协议与 redact 响应的**增量 map 下发**（只含本次新增映射；mask 模式下发打码值）。映射键口径与 `before_llm` 一致（`hooks.session_id()` 哈希）。
- **证据位置**：
  - 源码断言：`tools/release_gate.py --only 4` → PASS（plugin_display / server_restore 全命中）
  - 行为冒烟：`tests/js/plugin_display.mjs` 6 条（无映射透传、跨 chunk 分裂不丢字符、扣尾缓冲、end 兜底、start 清缓冲）；`tests/js/plugin_jobs.mjs` 13 条原用例不回归
  - 闭环验证：redact→map→restore(full) 逐字还原（`full_ok=true`）；mask 值形如 `13*******78`、`z***@example.com`
  - 残余说明：B 依赖 `agent/assistant-stream` 非公开契约（dsh 0.2.2-rc.1 实测可用），dsh 升级需复验；用户把还原后的明文复制进输入框属于使用约定问题，插件不可拦截

## 5. 格式覆盖面

- [x] **判定标准（文本类）**：md/txt/csv/json/xml 经 read 拿到的内容必须是已脱敏文本。
- **当前状态**：文本类 PASS；office 类“不泄露但不可用”；pwsh 前台已按 P1-全纳入（PASS，2026-11-06 拍板）。
- **证据**：
  - md/txt/csv/json：读取侧拦截生效（csv 实测 PERSON/ID/PHONE/ORG 计数 > 0）
  - docx/xlsx/pptx 经 read：原始字节 UTF-8 解码后占位符 0、PII 明文 0 —— 因 zip DEFLATE 压缩，内容本身不可用，**不构成泄露**，但用户也读不到内容；此类文件应走 CLI 产物级 redact/restore
  - rg 对 docx 内证件号默认 `exit=1`，加 `--text` 仍 `exit=1`
- [x] **shell（pwsh 前台 + 后台任务 + isError）输出**：PASS —— 插件 `GUARDED_TOOLS = {read, grep, pwsh, job_output, job_list}`；`job_output`/`job_list` 单块超过 256,000 字节先截断再脱敏并追加截断标记；非文本输出（NUL>1% 或不可打印>30%）不脱敏并追加标记行；shell/后台任务的 `isError` 文本同样脱敏（read/grep 的 `isError` 维持透传）；逃生开关 `PII_GUARD_SHELL=off`（对 pwsh 与后台任务生效）/ `PII_GUARD_SHELL_ALLOWLIST=<regex>`（仅 pwsh），命中写 `shell_bypass` 审计，不含明文。
  - 引擎级语义回归：`tests/test_shell_redaction.py` 23 条（14 条无 PII 日常输出逐字节不变、9 条含 PII 的结构保持与还原）
  - 插件行为冒烟：`tests/js/plugin_jobs.mjs` 13 条（job_output/job_list 脱敏、256 KB 截断上限、无 PII 不变、job_kill 放行、非文本标记、read 仍拦、pwsh/job isError 脱敏、read isError 透传、Python 服务 spawn 失败降级透传不崩溃、非法 allowlist 正则不放行），由门禁 #5 调用 node 执行
  - 一键门禁 #5：插件源码断言（含 job 工具、截断常量、isError 范围）+ node 冒烟 + 引擎语义抽查
  - 插件已纳入仓库：`plugins/dsh-pii-guard/lib/index.js`（sha256 `B43F93AF…E4071`，与安装态 `E:/Code/dsh_home/plugins/dsh-pii-guard/lib/index.js` 逐字节一致；#5 比对 sha256，drift 即 FAIL，反向验证：改动仓库副本 → FAIL，恢复 → PASS）
  - 修复一处连带缺陷：归一化曾吞掉数字间的连续空白，把 Get-Process 表格列拼成伪卡号；现改为只吞单个分隔符
  - 未覆盖（P3 剩余）：base64/UTF-16/图片内文字（已知缺口，见决策备忘 §3）；bash 同构（本机无 bash）
  - 进程内 E2E 随 #2 重启后人工跑（手动步骤 6–9）；isError 在进程内不易稳定触发，仅由 node 冒烟覆盖

## 6. 依赖漏洞

- [x] **判定标准**：`pip check` 无破损依赖；`pip-audit` 对安装集合报 0 条已知漏洞。
- **当前状态**：PASS
- **证据**：
  - 升级前后：`pillow 12.3.0 → 13.0.0`（原 41 条 advisory）；`certifi 2026.7.22 → 2026.10.18`（原 PYSEC-2026-4320）
  - `pip check` → No broken requirements
  - `uvx pip-audit -r <freeze 去掉本地 git 包>` → `No known vulnerabilities found`
  - 说明：audit 输入须剔除 `presidio-pii-dsh` 的 `-e git+ssh://…@ea22be4…` 行，否则 pip-audit 会尝试拉未推送的远端 ref 而失败（不是漏洞，是溯源问题，见第 10 项）

## 7. 密钥扫描

- [x] **判定标准**：工作树与全部可达历史中无真实凭据；命中项须逐条定性，真凭据需轮换。
- **当前状态**：PASS（0 个真凭据，无需轮换）
- **证据**：
  - 工具：PATH 无 gitleaks → 自写 `git log -p --all --no-color` + 12 类正则（AWS key、PRIVATE KEY、GitHub token/PAT、Slack、Google API key、`sk-`、JWT、secret/key/token/password 赋值、URI 带凭据、bcrypt、PEM 证书）
  - 结果：`commits_scanned=31`、`diff_lines=12038`、`hits=1`
  - 唯一命中：commit `fc3a70a5`，类型别名 `Token = Tuple[...]`（词性标注类型），**误报**，非凭据
  - 工作树：仅 `pyproject.toml` 修改（构建配置），无敏感文件
- **覆盖与漏检说明**：
  - 覆盖：所有分支/tag 可达提交的文本 diff + 提交消息
  - 漏检可能：二进制/图片 diff 内嵌内容、reflog 与不可达对象（dangling）、submodule 内部历史、上述 12 类之外的私有云格式与高熵随机串（无固定前缀）
  - 结论：作为"无已知凭据泄露"的证据足够；如需更强保证，需在联网环境装 gitleaks 并加 `gitleaks git --log-opts="--all"`

## 8. 单元测试套件

- [x] **判定标准**：`pytest -q` 全绿，无 skip 掩盖失败。
- **当前状态**：PASS —— `160 passed`（`D:\Python\313\python.exe -m pytest -q`；含 9 条结构保持/数字误报回归、5 条日志去明文与轮转、23 条 shell 输出语义回归用例）
- **证据位置**：`tests/`（`test_engine.py`、`test_flow.py`、`test_structures.py`、`test_variants.py`、`test_custom_rules.py`、`test_shell_redaction.py`）

## 9. 可复现安装

- [x] **判定标准**：不依赖未推送 git ref，仅用本地构建产物即可安装；安装后 `presidio-pii redact/restore` 在干净环境可运行且无损。
- **当前状态**：PASS
- **证据**：
  - 产物：`dist/presidio_pii_dsh-0.1.0-py3-none-any.whl`（57,350 B）。可复现哈希：`SOURCE_DATE_EPOCH=1700000000` 下连续两次构建均得 SHA256 `75050E227825CF06C5C7146D2A484F103EFA9D2DB954957FABDF3D7E66B0361A`（zip 条目时间戳与顺序均一致；随 shell/日志/归一化修复重建）。旧哈希 `097965DC…0234`、`5A154716…7C20` 不作发布依据。
  - 构建后端已锁定：`pyproject.toml` 的 `requires = ["setuptools==84.2.1", "wheel==0.48.0"]`（锁定前后 wheel 哈希同为 `75050E…0361A`，证明本次产物未受后端浮动影响；升级后端必须重建并更新清单）。详见 [RELEASE-RUNBOOK.md](RELEASE-RUNBOOK.md) 第 2.2 节。
  - 一键检查：`tools/release_gate.py` 第 9 项会构建两次比对哈希，并做干净 venv 安装与 CLI 往返。
  - 构建配置：`pyproject.toml` 新增 `[build-system]`、`[tool.setuptools.packages.find] include=["presidio_pii*"]`、`[tool.setuptools.package-data] presidio_pii=["assets/*.txt"]`
  - 干净环境：`C:\Users\sergg\AppData\Local\Temp\pii_venv_7054b1`（uv，py3.13），非 editable；`presidio_pii.__file__` 指向该 venv `site-packages`，`assets_ok=True`
  - CLI 验证：`presidio-pii.exe redact/restore` 正常；`paper.md` `md_identical=True`，`resume.docx` `docx_units_equal=True`；重建后的 wheel 重装后 `ws_equal=True`、`epoch_hits=0`、`uuid_hits=0`
  - CSV 判据补充：还原后逐单元格一致（`rows_equal=True`，2 行 × 5 列）；容器字节不一致属既有行为（输出带 BOM + CRLF，与本次 detector 改动无关）

## 10. 源码可溯源（origin 是否含 HEAD）

- [x] **判定标准**：发布包对应的提交在远端可达（`origin` 含 HEAD），**或**发布物改为已构建 wheel 并记录哈希。
- **当前状态**：PASS（按路径 A：远端可达）。2026-11-10 已提交并推送，`origin/master` 含 HEAD（`69021c9`），ahead 0；清单仍保留 wheel 哈希与源码树摘要作为产物级佐证。
- **证据**：`release/presidio-pii-dsh-0.1.0.json`
  - `artifact.sha256` = `75050E227825CF06C5C7146D2A484F103EFA9D2DB954957FABDF3D7E66B0361A`，bytes=57,350，与 `dist/` 中的 wheel 逐字节核对一致
  - `source.source_tree_sha256` = `f0446a21…7bec7`，由 `presidio_pii/**` + `pyproject.toml` 的路径/内容哈希排序后再哈希得到；门禁会按当前源码重算比对，源码一改即 FAIL，避免“清单绑定旧代码”
  - `source.commit` = HEAD（ea22be4），`provenance_mode = artifact-only`，并显式记录 `working_tree_dirty = true`
- **验证**：`python tools/release_gate.py --only 10` → PASS；把清单里的 sha256 改成假值后同一检查立即 FAIL（`sha_ok=False`），恢复后重新 PASS
- **残余说明**：wheel 产自未提交工作树，清单已记录该事实；远端可达路径 A 仍是更强的溯源形式，后续推送后门禁优先按 A 判定

## 11. 仓库不落真实 PII / 映射库

- [x] **判定标准**：真实语料、映射库、脱敏产物均不入版本库。
- **当前状态**：PASS
- **证据位置**：`.gitignore` 已忽略 `.pii_presidio_store/`、`*.mapping.csv`、`*.session.csv`、`*-redacted/`、`*-restored/`、`testdata/`、`testdata_v2/*`（保留 `!testdata_v2/negative/`）、`sim_*.jsonl`、`build/`、`dist/`、`eval_result.json`、`.review_tmp/`；`git status --porcelain` 仅有源码/测试/文档改动与 `release/` 清单，无真实语料、映射库或脱敏产物

## 12. 外部语料（网络下载）回归

- [x] **判定标准**：测试文件只能来自网络公开样例；注入合成 PII 后 redact→restore 逐字无损、占位符清零、明文中无注入值。
  不允许用本地语料或自造文件替代。
- **当前状态**：PASS（2026-11-07）
- **证据**：`tools/external_corpus_check.py`（下载缓存只放系统临时目录，不入库；报告不打印正文）

| 样例 | 来源 | 大小 | 单元 | 替换 | 逐字还原 | 残留 | 泄漏 |
|---|---|---|---|---|---|---|---|
| docx | filesamples.com sample1.docx | 1,311,881 B | 359 | 1,436 | True | 0 | 0 |
| xlsx | filesamples.com sample1.xlsx | 29,380 B | 785 | 3,140 | True | 0 | 0 |
| pptx | apache/poi SampleShow.pptx | 39,083 B | 10 | 40 | True | 0 | 0 |
| csv | filesamples.com sample1.csv | 502 B | 1 | 4 | True | 0 | 0 |
| txt | filesamples.com sample3.txt | 3,541 B | 1 | 4 | True | 0 | 0 |

- 门禁 #12 在线时自动下载并跑上述回归；离线时标 **SKIP** 并说明“不允许用本地语料替代”，不会静默通过。

---

## 整体过一遍的顺序

1. ~~勾第 2 项~~：✅ 已完成（2026-11-10）——DSH 完全退出 → 重启 → 选 `presidio-pii` → 9 步实测全 PASS，证据见 `.pii_presidio_store/e2e_9steps_2026-11-10.md`
2. 决策第 4 项（restore 接线 A/B/C），决策后补实现与用例；第 5 项已按 P1-全 + P2 实现
3. 第 10 项已按 B（产物级溯源）通过：清单在 `release/presidio-pii-dsh-0.1.0.json`；重建 wheel 或改源码后必须更新清单，否则 #10 转 FAIL。若后续决定推送，门禁会自动优先按“远端可达”判定
4. 每项勾选时把证据落盘路径写进本文件，避免"口头通过"
