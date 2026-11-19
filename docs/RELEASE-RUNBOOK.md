# 发布 Runbook（v0.1.0）

> 用途：发布前后的操作手册。状态刷新于 2026-11-17（文档整理）；数据以 [RELEASE-GATE.md](RELEASE-GATE.md) 为准，未拍板处标 **待定**，不代替决策。
> 配套文件：[RELEASE-GATE.md](RELEASE-GATE.md)（逐项判据与证据）、[DECISION-shell-redaction.md](DECISION-shell-redaction.md)（shell 与 restore 决策材料）。

## 0. 当前基线

| 项 | 值 |
|---|---|
| 包名 / 版本 | `presidio-pii-dsh` / `0.1.0` |
| 提交 | `HEAD a31dac6`（2026-11-17，未推送）；`origin/master = 59573a4`，ahead **3**；最近已推送发布提交 `69021c9`（2026-11-10）|
| 构建产物 | `dist/presidio_pii_dsh-0.1.0-py3-none-any.whl`，66,668 B；清单 `release/presidio-pii-dsh-0.1.0.json` 绑定 HEAD `a31dac6`（artifact-level 产物级溯源），哈希 `8C99677F…6BE6E` |
| 可复现哈希 | 历史值：2026-11-10 `75050E22…0361A`（57,350 B）、`69021c9` `77154909…20CF8`（58,831 B）仅作对照；当前清单值为 `8C99677F…6BE6E`（66,668 B，HEAD `a31dac6`）；再次发布须按第 2 节重算 |
| 一键门禁 | `python tools/release_gate.py`（`--json` 落盘逐项结果） |
| 最近一次门禁 | **PASS 11 / FAIL 1 / SKIP 0 / MANUAL 0**（2026-11-16 晚，屏蔽词 UI 落地后全量；#8 222 passed，#9 wheel 两次一致 61,357 B；深夜 FP 修复后单测 228 passed）。唯一 FAIL 为 #6 环境级 `opentelemetry-api 1.45.1` / `CVE-2026-126360`（fix 1.45.2，与本轮代码无关）。当前 #10 按路径 B（产物级）判定，清单绑定 HEAD `a31dac6`；HEAD 未推送，正式发布前须推送（转 A）或重生成清单维持 B（见第 5 节） |

## 1. 发布前检查

1. 跑一键门禁，逐项确认，不允许把 SKIP/MANUAL 当作通过：

   ```powershell
   python tools\release_gate.py --json "$env:TEMP\release_gate.json"
   ```

   判读：
   - 退出码 0 = 全 PASS，1 = 有 FAIL，2 = 无 FAIL 但仍有 SKIP/MANUAL。
   - #1 读取侧引擎、#3 redact→restore、#5 shell、#6 依赖、#7 密钥、#8 pytest、#9 wheel、#10 溯源、#11 仓库不落 PII 必须是 PASS。
   - #12 外部语料（网络下载）：联网时必须 PASS；离线为 SKIP 并在发布记录里写明（不得用本地语料替代）。
   - #10 溯源：当前按路径 B（产物级）判定——清单绑定 HEAD `a31dac6`（`8C99677F…6BE6E`、66,668 B，`artifact-level`）；HEAD 未推送，正式发布前须推送（转 A）或重生成清单维持 B（见第 5 节）。旧口径「路径 A / `69021c9`」仅作对照。
   - #4 restore 接线：已拍板方案 B 并实现，**PASS**（`PII_GUARD_DISPLAY=full/mask/off`）；#5 为 PASS。
   - #2 DSH 进程内 E2E：**PASS**（2026-11-10 重启后 9 步实测，证据见 `.pii_presidio_store/e2e_9steps_2026-11-10.md`）。

2. 确认发布对应的是哪份源码（清单绑定 HEAD `a31dac6`，含工作树未提交的后续修复与本次文档整理，见 `git status --porcelain`）：

   ```powershell
   git status --porcelain
   git rev-parse HEAD
   ```

3. 依赖与测试基线（脚本已包含，失败即阻断）：
   - `pytest -q` → 228 passed
   - `pip check` → 无破损依赖；`pip-audit` → 当前环境有 1 条已知漏洞（`opentelemetry-api 1.45.1` / `CVE-2026-126360`，fix 1.45.2，属环境级、与本轮代码无关；修复后重跑 #6）
   - 无凭据命中（历史 31 commits；工作树文件数见门禁 #7 证据）
   - 外部语料回归（网络下载 docx/xlsx/pptx/csv/txt，注入合成 PII 后逐字无损）；离线时该项为 SKIP，不得以本地语料替代

## 2. 构建可复现产物

固定 zip 时间戳后再构建，连续构建两次必须字节一致：

```powershell
$env:SOURCE_DATE_EPOCH = "1700000000"   # 或改为发布提交的 commit time
Remove-Item -Recurse -Force build, presidio_pii_dsh.egg-info -ErrorAction SilentlyContinue
python -m pip wheel . --no-deps -w dist --disable-pip-version-check
Get-ChildItem dist\*.whl | ForEach-Object {
  "{0} {1}B {2}" -f $_.Name, $_.Length, (Get-FileHash $_.FullName -Algorithm SHA256).Hash
}
```

重复上面两条命令（换一个输出目录）比对哈希。当前清单（`release/presidio-pii-dsh-0.1.0.json`，HEAD `a31dac6`）绑定产物 `8C99677F5FF302C0FA97D952F2C28A4706AE73139010B05E418326C431A6BE6E`、66,668 B，两次构建须一致；历史值 `75050E22…0361A`（57,350 B）、`77154909…20CF8`（58,831 B，提交 `69021c9`）仅作对照。以当天发布提交重算为准。

建议按门禁脚本的做法从**源码副本**构建（`tools/release_gate.py` 的 #9 会复制 `presidio_pii/` + `pyproject.toml` 到临时目录再构建两次）：
避免仓库内 `build/lib` 的陈旧文件被带进 wheel，也不在工作树留生成物。

### 2.1 必须记录的产物信息

| 字段 | 本次值 / 取法 |
|---|---|
| wheel 文件名 | `presidio_pii_dsh-0.1.0-py3-none-any.whl` |
| 大小 / SHA256 | 当前清单值 66,668 B / `8C99677F5FF302C0FA97D952F2C28A4706AE73139010B05E418326C431A6BE6E`（历史值 58,831 B / `77154909…20CF8`、57,350 B / `75050E22…0361A` 仅作对照） |
| `SOURCE_DATE_EPOCH` | `1700000000`（发布时应改为发布提交时间并重新记录哈希） |
| 源码提交 | 清单绑定 HEAD `a31dac6`（artifact-level 产物级溯源，含未提交工作树修复）；推送后自动转 origin-reachable 路径 A |
| 构建后端（已锁定） | `setuptools==84.2.1` / `wheel==0.48.0`（`pyproject.toml` 固定，pip 隔离构建解析结果 `packaging 26.3`） |
| 构建命令 | 第 2 节两条命令，原样记录 |
| 产物出处清单 | `release/presidio-pii-dsh-0.1.0.json`（wheel 哈希 + 源码树摘要 + HEAD，门禁 #10 复核） |
| 门禁 JSON | `$env:TEMP\release_gate.json` 复制归档（含逐项证据） |
| 测试与审计 | `228 passed`；`pip-audit` 当前 #6 FAIL（环境级 `opentelemetry-api 1.45.1` / `CVE-2026-126360`） |

### 2.2 残余不可复现因素（如实说明）

- **已消除**：zip 内条目时间戳（`SOURCE_DATE_EPOCH` 生效，实测条目 `date_time` 全部为 `2023-11-14 22:13:20`）；条目顺序（两次构建相同）。
- **未消除：跨操作系统构建差异**（Linux/macOS 未验证）；仅在本机 Windows + 上述锁定后端上验证了两次构建一致。
- 说明：2026-11-10 锁定前后 wheel 哈希同为 `75050E…0361A`，说明当次产物未受后端版本浮动影响；升级锁定版本必须重建 wheel 并更新 `release/*.json`，否则门禁 #10 会 FAIL。
- `dist/` 当前 wheel 与清单绑定的 HEAD `a31dac6` 一致（`8C99677F…6BE6E`，66,668 B）；历史产物 `77154909…20CF8`（`69021c9`）、`75050E…0361A` 已不在目录中，不能作为发布依据。源码再变须重跑 #9/#10 并更新清单。

## 3. 干净环境安装验证

门禁 #9 已自动完成：新建 venv → `pip install --no-index --no-deps <wheel>` → 校验非 editable、`assets/surnames.txt` 存在 → `paper.md` redact→restore 字节一致。

手工复核：

```powershell
python -m venv "$env:TEMP\pii_release"
& "$env:TEMP\pii_release\Scripts\python.exe" -m pip install --no-index --no-deps (Get-ChildItem dist\*.whl).FullName
& "$env:TEMP\pii_release\Scripts\presidio-pii.exe" redact testdata_v2\paper\paper-01.md
& "$env:TEMP\pii_release\Scripts\presidio-pii.exe" restore testdata_v2\paper\paper-01-redacted\paper-01.md -d "$env:TEMP\pii_release\restored"
```

还原文件应与原文字节一致（`Get-FileHash` 比对）。

## 4. MANUAL：DSH 进程内 E2E（需人工）

插件用普通 `import`，改文件后必须**完全重启** DSH 进程才加载。

1. 托盘图标右键 → **完全退出** DSH（不是关闭窗口）。
2. 重新启动 DSH，选择 `presidio-pii` 预设。
3. `read testdata_v2/paper/paper-01.md`（前 8 行）：出现 `⟦PII:PERSON:xxxx⟧`，且无明文人名。
4. `read testdata_v2/negative/normal-01.md`：PERSON / ID_NUMBER / PHONE_NUMBER / BANK_CARD 计数均为 0。
5. `grep 13800000000`：命中行中的电话已变为占位符。
6. `pwsh` 执行 `Get-Content testdata_v2/paper/paper-01.md`：输出含占位符、无明文人名（P1-全拦截生效）。
7. `pwsh` 执行无 PII 命令（`git status`、`Get-Process`）：输出与未拦截时逐字节一致。
8. `pwsh` 后台跑 `Get-Content testdata_v2/paper/paper-01.md`，再用 `job_output` 续读：输出含占位符、无明文人名。
9. `job_list` 查看任务：命令/描述回显里的人名与电话已变占位符。

通过判据：上述 9 步均符合，且 `.pii_presidio_store/hook_log.jsonl` 新增对应 `before_llm` 记录（`n_replaced > 0`，日志不含明文）。
插件文件位置：`<DSH_HOME>/plugins/dsh-pii-guard/lib/index.js`；仓库内已有版本化副本 `plugins/dsh-pii-guard/lib/index.js`（门禁 #5 逐字节比对，drift 即 FAIL）。修改流程：先改仓库副本 → 用 `Copy-Item plugins\dsh-pii-guard\lib\index.js <DSH_HOME>/plugins/dsh-pii-guard/lib/index.js -Force` 同步 → 完全重启 DSH → 跑 `tools/release_gate.py --only 5`。

## 5. #10 溯源决策（当前口径：路径 B 产物级；推送后转 A）

工作树含未提交修复（HEAD `a31dac6`，`origin/master = 59573a4`，ahead 3），远端尚不包含发布提交。因此门禁 #10 **当前按路径 B（产物级溯源）判定**：wheel 字节哈希 + 源码树摘要 + HEAD 三者一致即 PASS；待发布提交推送到 `origin/master` 后，自动转路径 A（远端可达）。一切以 `release/presidio-pii-dsh-0.1.0.json` 为准。

- **B（当前口径）**：`release/presidio-pii-dsh-0.1.0.json` 记录 `artifact.sha256 = 8C99677F5FF302C0FA97D952F2C28A4706AE73139010B05E418326C431A6BE6E`、`bytes = 66,668`、`source.commit = a31dac6`、`provenance_mode = artifact-level`；脚本重算 wheel 哈希与源码树摘要，未推送时两者必须与当前源码一致才 PASS。
- **A（推送后生效）**：`git push origin master` 后，门禁检查 `HEAD` 是否已被 `origin/master` 包含（脚本 `tools/release_gate.py` 的 `check_provenance`，`origin_ok` 路径）；清单 `note` 已注明「推送后自动转路径 A」。历史值 `77154909…20CF8` / 58,831 B / `69021c9` / `origin-reachable` 属旧口径，仅作对照，不再作为判定依据。

维护规则：正式发布前把发布提交推送到 `origin/master`（转 A），或重建 wheel 并同步更新清单（含 `bytes`/`sha256`/`commit`/`source_tree_sha256`，维持 B），否则 #10 转 FAIL。
无论哪条，**不发布未固定时间戳的产物**。

## 6. 回退方案

前提：2026-11-10 已将 `69021c9` 推送到 `origin/master`，远端已有可回退基线；当前 HEAD `a31dac6` 尚未推送（ahead 3）。回退目标是已推送的 `69021c9`（含显示侧还原与首轮修复，但不含 11-11 之后的 shell/FP/屏蔽词等修复），更早基线 `7188dbaa`（2026-10-31）不含本次全部修复。

### 6.1 立即回退（若上线后发现阻断问题）

1. 回退插件：仓库副本 `plugins/dsh-pii-guard/lib/index.js` 已纳入版本控制，直接用它覆盖
   `<DSH_HOME>/plugins/dsh-pii-guard/lib/index.js`，完全重启 DSH，再跑 `tools/release_gate.py --only 5`
   （仓库副本即发布基线，不再依赖手工 `.bak`）。
2. 回退 Python 包：在干净 venv 里卸载当前版本，改用已推送提交 `69021c9` 的历史产物（哈希 `77154909…20CF8`、58,831 B，旧口径仅作回退基线；当前清单产物为 HEAD `a31dac6` 的 `8C99677F…6BE6E`）。该历史版本不含 11-11 之后的修复，回退前评估功能损失。
3. 回退数据（可选）：把 `.pii_presidio_store/` 下的映射库替换为发布前快照（发布前应先做快照）。

### 6.2 验证回退成功

- 门禁子集：`python tools/release_gate.py --only 1,3,8` 全 PASS。
- CLI：`paper-01.md` redact→restore 后字节一致。
- 读取侧签名可用于区分版本：
  - 当前（含修复）：`paper-01` 共 **12** 处，`PERSON 8 / ORGANIZATION 2 / LOCATION 1 / EMAIL_ADDRESS 1`。
  - 回到 `69021c9`（首轮修复）：预期该基线的脱敏行为（不含后续 shell/FP/屏蔽词修复）；更早的 `7188dbaa`（2026-10-31，无修复）预期 **13** 处、`PERSON 9`（多出的 1 处是章节标题「方法」的误报），且可能出现人名吞空格/13 位时间戳误判。
- 插件侧：重启后 `read paper-01` 无明文人名，`hook_log.jsonl` 有新增脱敏记录。

## 7. 上线后 24 小时观察

| 观察项 | 具体看什么 | 异常信号 / 处置 |
|---|---|---|
| 脱敏有效性 | 抽样当日 read 输出，检查是否出现明文手机号/身份证/银行卡（只记录条数，不复制明文） | 出现明文 → 立即回退（第 6 节） |
| `hook_log.jsonl` | 新增行数、`n_replaced` 分布、`entities` 类型分布、JSON 解析失败行数（只含元数据，不含原文） | 本次观测：81 行中 16 行解析失败（清洗时已丢弃）；若失败行持续增长 → 并发写/截断问题，需排查 |
| 日志落盘风险 | 日志已改为只存元数据（实体类型/数量、内容指纹、`conv_sha1`/`doc_sha1`）；原文仅在 `sessions.db` | 文件仍须留在 `.gitignore` 内、限制访问；轮转上限 10 MB（超限改名 `hook_log.jsonl.1`） |
| 延迟 | 大文件 read 的耗时（引擎吞吐约 0.8 MB/s，64 KB 约 88 ms） | 明显变慢 → 检查 Python 服务是否重启/排队 |
| 插件异常 | DSH 日志中的 `[pii-guard] redact failed, blocking result` 告警与工具结果被 `[pii-guard]` 阻断 | 出现即表示 Python 脱敏服务不可用（fail-closed 已生效，明文未放行）；查 `PII_GUARD_PY` / 服务进程后重启插件。**不要**为此设置 `PII_GUARD_FAIL_OPEN=1` 绕过 |
| 误伤反馈 | 表格对齐、路径被替换导致命令失败、JSON 仍可解析但值不可回填 | 按 [DECISION-shell-redaction.md](DECISION-shell-redaction.md) 第 4 节的处置口径记录 |
| 磁盘增长 | `.pii_presidio_store/`（`sessions.db`、映射库、日志） | 设定清理策略 **待定** |

## 8. 待定事项清单（发布前需用户拍板）

1. ~~restore 自动接线~~ → 已拍板**方案 B**（2026-11-10）：`agent/assistant-stream` 显示侧还原 + `PII_GUARD_DISPLAY=full/mask/off` 三档设置；门禁 #4 已转 PASS（`tools/release_gate.py --only 4`），冒烟 `tests/js/plugin_display.mjs` 6 条。C 方案（llm/stream）明确排除——违背"PII 不进模型上下文"不变量。
2. shell 已拍板 P1-全 + P2 + isError（pwsh 前台 + `job_output`/`job_list` + 错误文本，2026-11-06/07 实现，含 256 KB 截断）；剩余待定：base64/UTF-16/图片内文字、bash 同构。
3. ~~溯源已选 B~~ → 2026-11-10 已提交推送，升级为 A（origin 含 HEAD），当时门禁 #10 PASS。当前 HEAD `a31dac6` 尚未推送（ahead 3），2026-11-17 复跑 `--only 10` FAIL；发布前须推送并重生成清单。
4. ~~是否提交~~ → 发布提交 `feb0e55` + `69021c9` 已推送；`69021c9` 之后的修复（含 `a31dac6`）未提交/未推送，打 tag 仍待定。
5. ~~是否锁定构建后端版本~~ → 已锁定 `setuptools==84.2.1` / `wheel==0.48.0`（2026-11-07，门禁 #9 复核）；跨 OS 复现仍未验证。
6. `hook_log.jsonl` 的保留期限与访问控制（明文问题已于 2026-11-06 修复：只存元数据，不再写原文）。
7. 已知检测缺口是否接受为残余风险：base64/UTF-16/图片内文字、bash 同构（见 [DECISION-shell-redaction.md](DECISION-shell-redaction.md) §3）。
