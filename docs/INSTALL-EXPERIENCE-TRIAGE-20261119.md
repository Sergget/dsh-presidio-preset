# 安装体验报告核实与后续修复计划（2026-11-19）

## 背景与口径

外部设备（Windows 11 / DSH 0.2.2-rc.5 / profile=desktop / Python 3.9.13）安装体验报告列出 10 条问题（2×P0 / 4×P1 / 4×P2）。本文逐条用**只读证据**核实，不照单全收，结论分「属实 / 部分属实 / 不实」。核实命令在本文末尾「证据复现」列出，所有行号基于工作树当前版本（HEAD aaa3508 + 未提交修复）。

**核实结论分布**：属实 7（P0-1、P0-2、P1-3、P1-4、P1-5、P1-6、P2-7）、部分属实 3（P2-8、P2-9、P2-10）。无纯不实条目——报告整体质量高。

## 一、逐条核实

### P0-1　硬编码作者本机路径 — 属实

- 证据：`git grep -E 'E:[/\\]Code[/\\]'` 全仓库（排除 .git/node_modules）命中 97 处；仅源码/配置（排除备份/临时目录）命中 57 处，路径变体分布：`E:\Code\dsh-presidio-preset` 28、`E:/Code/dsh_home` 20、`E:/Code/dsh-presidio-preset` 10、`E:\Code\dsh_home` 9 —— **路径指向两类目录**（`dsh-presidio-preset` 仓库根 与 `dsh_home` DSH 主目录），且同一目录有正/反斜杠两种写法，报告所称"路径自身不一致"属实。
- 更正：外部报告称"有的写 `E:/Code/dsh-presidio-pii`（少 reset）"——**当前仓库核实不成立**。精确复核（`E:[/\\]Code[/\\][A-Za-z0-9_-]+` 词边界匹配）只有 `dsh-presidio-preset` 与 `dsh_home` 两种目录名，无 `dsh-presidio-pii` 裸变体。报告可能将包名 `@local/dsh-presidio-pii-preset`（`.agent-presets/presidio-pii/bundle/package.json:2`）误读为路径。
- 关键不可覆盖点：`.agent-presets/presidio-pii/bundle/cordis.patch.yml:110` 的 `file:///E:/Code/dsh_home/plugins/dsh-pii-guard/lib/index.js`、:115 的 `customSkillDirs: E:/Code/dsh-presidio-preset/.agent-presets/presidio-pii/skills` —— bundle patch 内路径无环境变量覆盖，换机必须改文件，属实。
- 可覆盖点：`plugins/dsh-pii-guard/lib/index.js:61`、`plugins/dsh-pii-guard-terms/lib/index.js:45` 已支持 `PII_GUARD_REPO` 覆盖（报告也承认），但默认值是作者路径，普通人不知道要设。
- 报告"29 处"与本机核实 97 处差异：统计口径不同（是否含备份/临时/文档），不影响结论。

### P0-2　离线/受限网络不可安装，release 只有 manifest 没有 wheel — 属实

- 证据：`release/` 目录仅 `presidio-pii-dsh-0.1.0.json`（manifest），无 wheel 本体。wheel 实体在 `dist/presidio_pii_dsh-0.1.0-py3-none-any.whl` 与 `.pii_presidio_store/build_tmp/pii_b{1,2}/`，而 `.gitignore:24` 忽略 `dist/`；`git ls-files dist/* release/*` 只返回 manifest。
- README.md:26-27 只有 `pip install -e .` / `pip install -e ".[segment]"`，无离线章节；全仓库文档搜 "离线|offline|wheel|vendored" 仅命中 README.md:5 的"全程离线运行"（指运行时，非安装）。
- 影响属实：主打本地/air-gapped 的项目，clone 后却必须联网 pip 装构建依赖。报告所述 setuptools 58.1 / wheel 0.47 不支持 PEP 660 的场景在当前 manifest（setuptools 84.2.1 / wheel 0.48.0 固定）下确实会炸。

### P1-3　校验脚本在当前 DSH 安装形态下无法运行 — 属实

- 证据：`tools/verify_preset_plugins.mjs:25-28` 用 `npm root -g` 作为 `DSH_NODE_MODULES` 默认值，:31 `createRequire(resolve(DSH_NODE_MODULES, "@deepseek-ai/dsh/package.json"))`。本机 DSH 核心包打包进 app.asar，全局 npm root 无 `@deepseek-ai`，脚本会在 :33 `dshRequire("yaml")` 处抛错。
- 脚本注释明说"可用 DSH_NODE_MODULES 覆盖"，但无 app.asar / profile node_modules 的 fallback，符合报告描述。

### P1-4　安装后校验方式不明确，缺少一键自检 — 属实

- 证据：README.md 无"安装成功判定"命令，无 verify-install 脚本；START-HERE.md / STEP5-VERIFY.md 是**脱敏效果验证流程**（素材工具自检、语料跑分），非"安装是否生效"检查。
- bundle patch 通过 link 注入、不写进 profile patch 文件的事实成立（README.md:135-136 描述了 UI bundle 的 link 安装，agent bundle 同理），用户 grep profile patch 会得到错误结论。`plugin_manager list_bundles` 是正确判定方式，但文档未写。

### P1-5　preset.json 声明 DSH 0.2 已不使用的遗留 hook — 属实

- 证据：`.agent-presets/presidio-pii/preset.json:5-15` 声明 `entrypoint: "hook.py"` + `on_before_llm` / `on_after_llm` 两个 handler；`hook.py` 仅 9 行薄 shim（转发 `presidio_pii.hooks`）；README.md:127-130 明说"当前 dsh 0.2.x 不提供此接缝"，但同时说明 `preset.json` 本身**仍是活的配置源**（`entity_types`、`config.whitelist_path`、`config.custom_rules_path` 由 `presidio_pii/hooks.py` 读取，设置页会写它）。
- 报告建议"移除声明"需谨慎：不能直接删 preset.json，否则丢活配置；应保留文件、只标注 hook 段 deprecated。报告"用户会误以为 hook 机制在工作"属实。

### P1-6　多个路径来源分散，漂移检测覆盖不全 — 属实

- 证据：`warnIfPathDrift` 仅在 `plugins/dsh-pii-guard-terms/lib/index.js:545-553,687`（UI 插件 Host 侧，需插件加载）；guard 侧（`resolveRepo`）与 bundle patch 路径无统一收敛。路径来源至少 6 类：preset.json:21 `custom_rules_path`、UI 的 termsFile/settingsFile/repo、guard 的 REPO、bundle patch 的 file URL + customSkillDirs。
- 与已修复的 S3（guard 认 config.repo）互补：S3 解决"config 传入"问题，但未解决"单一配置源"问题——`DEFAULT_REPO` 仍是兜底常量。

### P2-7　安装流程分散，缺少统一入口与一键脚本 — 属实

- 证据：README.md 快速开始只覆盖 Python 包（:24-40），DSH 插件安装散落在 README.md:131-152 与 START-HERE.md、各插件 README；无 `install-all` / `install.ps1` 脚本。用户需自己拼出"Python 包 → 复制 guard → 装 preset bundle → 装 UI bundle"顺序，属实。

### P2-8　运行时守卫默认 fail-closed，缺少显著风险提示 — 部分属实

- 证据：README.md:13 与 README.en.md:13 提到 fail-open 配置项，但措辞"仅排障"过于简略；`docs/SECURITY-NOTES.md:116` 的 fail-safe 章节讲的是**配置损坏**降级方向，不是**服务异常**的 guard 阻断行为。用户遇到"所有工具结果被吞"时，文档确实不足以定位——这一半属实。
- 不实的部分：设置页已有 failOpen 配置项（README.md:13 明列），报告自己也承认；"缺少显著提示"成立，"缺少开关"不成立。

### P2-9　Python 版本声明与实际不符 — 部分属实（当前报告所述声明已不存在）

- 证据：全仓库 markdown + pyproject.toml 核实，**当前无"Python 3.10–3.13"声明**；`pyproject.toml:15` 为 `requires-python = ">=3.9"`，README.md / README.en.md / docs 均无 3.10–3.13 字样。Python 3.9.13 跑通 demo 与声明一致。
- 报告可能基于旧版本 README（安装日期 2026-11-19，仓库此前已改过该声明）。结论：**当前代码库无此问题**，但报告提醒"版本声明要与安装校验对齐"值得纳入计划——`>=3.9` 无上限，3.14+ 未验证，建议显式测试矩阵。

### P2-10　clone 受全局 git 配置干扰，文档未覆盖 — 部分属实

- 证据：全仓库 markdown 搜 `ghproxy|insteadof|sslBackend|SEC_E_NO_CREDENTIALS|codeload` 零命中，文档确实无故障排查项（属实的一半）。
- 不属实的一半：这是**用户环境问题**，非仓库缺陷；`url.insteadof` 重写与 SSL 后端是全局 gitconfig / 系统证书导致，仓库能做的仅是"提供 zip 下载备选 + 文档排障项"，报告自己也标注"这主要是环境问题"。

## 二、后续开发与修复计划

按"先解 P0（换机不可用），再解 P1（校验/文档/遗留声明），P2 随迭代"排序。每条含验收标准，避免空口完成。

### 第一优先级（P0，换机可用性）

| 编号 | 任务 | 涉及文件 | 验收标准 |
| --- | --- | --- | --- |
| FIX-1 | 消除硬编码路径：bundle patch 的 file URL 与 customSkillDirs 改为相对/动态解析；提供 `install.ps1`（`-Repo/-DshHome` 参数）生成 patch | `.agent-presets/presidio-pii/bundle/cordis.patch.yml`、新增 `tools/install.ps1` | 在一台全新机器（不同 DSH_HOME、不同 repo 路径）执行一键安装后，guard 插件加载成功、skills 目录命中；全仓库源码/配置（排除备份/临时/文档）`E:/Code` 命中为 0 |
| FIX-2 | release 附带 wheel：CI/发布流程把 dist wheel 拷入 `release/` 并更新 manifest；README 增加"离线安装"章节 | `tools/release_gate.py`、`release/`、README.md / README.en.md | `clone --depth 1` 后无需联网即可 `pip install release/*.whl --no-deps`（依赖另给 vendored/离线清单）；manifest 的 sha256 与实际文件一致 |

### 第二优先级（P1，校验与文档）

| 编号 | 任务 | 涉及文件 | 验收标准 |
| --- | --- | --- | --- |
| FIX-3 | 修 `verify_preset_plugins.mjs`：支持 DSH_INSTALL_DIR / profile node_modules / app.asar 解析，失败给明确指引 | `tools/verify_preset_plugins.mjs` | 在 app.asar 形态 DSH 上执行脚本返回 0 且无解析错误；去掉 `DSH_NODE_MODULES` 后仍能定位依赖 |
| FIX-4 | 一键自检 `verify-install`：Python 导入、CLI demo、bundle enabled（plugin_manager list_bundles）、guard 加载、路径一致性 5 项 | 新增 `tools/verify_install.*`、README.md | 一条命令输出 5 项 PASS/FAIL 与失败原因；README 写明"安装成功判定" |
| FIX-5 | preset.json hook 段标 deprecated：保留文件（活配置源），在 hook 声明处加醒目注释与文档链接指向真正生效的插件路径 | `.agent-presets/presidio-pii/preset.json`、`hook.py` 注释、README.md:127-130 | 用户读 preset.json 首屏即知 hook 段在 0.2 不生效、真实路径在哪；entity_types 等活配置不被误删 |
| FIX-6 | 路径单一配置源 + 前置漂移校验：所有组件从一个配置读路径，漂移检测提为独立可手动运行脚本 | UI/guard 插件、bundle patch、新增 `tools/check_paths.*` | 改一处路径全链路生效；手动运行漂移脚本能检出跨组件不一致 |

### 第三优先级（P2，体验与健壮性）

| 编号 | 任务 | 验收标准 |
| --- | --- | --- |
| FIX-7 | 统一安装入口：README 顶部"推荐一键安装 / 手动安装"两条路径，安装脚本串起 4 步 | 新用户按 README 三步内完成安装，无需人肉改路径 |
| FIX-8 | fail-closed 风险显著提示：README、设置页 failOpen 旁说明行为与排障开关 | 遇到"工具结果被吞"时用户能在文档首屏找到 `PII_GUARD_FAIL_OPEN=1` |
| FIX-9 | 版本声明对齐：显式测试矩阵（3.9 起），安装时版本校验并给明确报错 | 3.9/3.10/3.13 至少各跑一次 CLI demo；超出范围版本安装时报错而非静默 |
| FIX-10 | 网络排障文档：git URL 重写 / SSL 后端排查项 + codeload zip 备选源 + release 源码包 | 文档覆盖 ghproxy/insteadof/SSL 后端三类问题的排查命令 |

### 与既有工作的衔接

- FIX-6 与报告 §五「配置页 UI 标签化」及 S3（config.repo 对齐）同属"路径/配置源收敛"主线，建议合并为一个 epic。
- FIX-4 与已落盘的 release_gate (#11) 有重叠：优先复用门禁的路径一致性检查，避免重复造轮子。
- 初版为核实结论与计划；2026-11-19 用户要求「全部执行」后 FIX-1～FIX-10 已全部实施，实施状态见「四、实施收口」。

## 三、证据复现（只读命令摘要）

| 核实项 | 命令要点 | 结论 |
| --- | --- | --- |
| 硬编码路径数量/变体 | `Select-String -Pattern 'E:[/\\]Code[/\\]'` + 分组统计 | 97 处全量 / 57 处源码配置，4 种变体 |
| 路径不一致 | 词边界精确匹配 `E:[/\\]Code[/\\][A-Za-z0-9_-]+` | 仅 `dsh-presidio-preset`/`dsh_home` 两类目录名（报告所称 `dsh-presidio-pii` 裸变体不成立，系包名误读） |
| wheel 缺失 | `Get-ChildItem -Filter *.whl`；`git ls-files dist/* release/*`；`git check-ignore -v dist/...` | 只在 gitignore 的 dist/ 与临时目录，release 仅 manifest |
| verify 脚本解析 | 读 `tools/verify_preset_plugins.mjs:25-33` | 默认 npm root -g，无 asar fallback |
| hook 遗留声明 | 读 `preset.json:5-15` + `hook.py`(9 行 shim) + `README.md:127-130` | 声明存在且 0.2 不生效，但 preset.json 仍是活配置 |
| 漂移检测范围 | `Select-String -Pattern 'warnIfPathDrift'` | 仅 UI 插件 Host 侧 :545-553,687 |
| 版本声明 | 全仓库 md + `pyproject.toml:15` 搜 `3.10|3.13|requires-python` | 当前无 3.10–3.13 声明，`>=3.9` |
| fail-open 提示 | README.md:13 / SECURITY-NOTES.md:116 | 配置项存在但提示简略 |
| git 排障 | 全仓库 md 搜 `ghproxy|insteadof|sslBackend|codeload` | 零命中 |

> 本节为核实阶段的只读证据。实施状态见下一节「四、实施收口」。

## 四、实施收口（2026-11-19，用户「全部执行」）

10 项 FIX 全部落地（FIX-1/6 由子代理实施，FIX-2/3/4/5/7/8/9/10 由主代理实施），逐项状态与证据：

| 编号 | 状态 | 实施要点 | 验证证据 |
| --- | --- | --- | --- |
| FIX-1 | ✅ | bundle/cordis.patch.yml 占位符化 `__REPO__`/`__DSH_HOME__`，pii-guard 条目补 `config.repo: __REPO__`（部署态 REPO 不为空）；两插件 `DEFAULT_REPO` 改 `inferRepoFromModule()` 哨兵推断；新增 tools/install.ps1 与 check_paths.ps1 | check_paths 零命中 exit 0；install.ps1 实跑 exit 0，installed 产物 pii-guard.repo 已注入真实路径 |
| FIX-2 | ✅ | dist wheel 拷入 release/（67562B）；manifest 重建绑定当前源码树 | gate --only 9,10 PASS 2/FAIL 0，commit_match/tree_digest_match 均 True |
| FIX-3 | ✅ | verify_preset_plugins.mjs 5 级解析链，显式 env 无效立即 exit 2 | node --check exit 0；正常 PASS / 无效 env exit 2 |
| FIX-4 | ✅ | 新增 tools/verify_install.ps1 五项自检 | 实跑 4 PASS / 0 FAIL / 1 SKIP（bundle 项需 DSH 会话内 plugin_manager，预期跳过），exit 0 |
| FIX-5 | ✅ | preset.json 加 `_deprecated_hooks_notice`；hook.py docstring 标 DEPRECATED | JSON 合法性 OK |
| FIX-6 | ✅ | 新增 tools/check_paths.ps1 独立漂移校验 | 实跑 exit 0；首跑揪出 4 处漏网（agent.cordis.yml 2、示例 1、脚本自身 1）已闭环 |
| FIX-7 | ✅ | README 双语新增「安装与部署」章节，推荐一键安装 + 手动安装 | 已更新 |
| FIX-8 | ✅ | README 显著提示默认 fail-closed，`PII_GUARD_FAIL_OPEN=1` 仅排障 | 已更新 |
| FIX-9 | ✅ | README/pyproject 声明 3.9~3.13；install.ps1 版本校验；本机 3.11/3.13 CLI demo 实测 | 3.13.13 / 3.11.9 demo 均 exit 0；install.ps1 版本校验 PASS（3.9/3.10 本机无解释器，未实测，如实记录） |
| FIX-10 | ✅ | README 双语补 git/SSL 排障 + codeload zip 备选源 | 已更新 |

**总验证**：全量 `pytest tests/` → 260 passed, 8 subtests passed, 0 fail（73.84s）；JS 三套烟测（terms 63 passed / display 含 S3 用例 PASS / jobs ALL PASS）+ tools/test-pii-guard.mjs 全 PASS；一键自检 4 PASS / 0 FAIL / 1 SKIP（预期）。

**收口核对**：临时探针/脚本（`_b4_probe.py`/`_b2_probe.mjs`/`_b1_probe.cjs`/`_finalize_release.py`/`_acl_probe/`/`_preset_probe/`）全部清理；敏感信息扫描零命中；check_paths 源码配置零硬编码路径。

**遗留风险（如实披露）**：
- bundle enabled 自检项在无 plugin_manager CLI 的 shell 中为 SKIP，需在 DSH 会话内 `plugin_manager list_bundles` 确认两个 bundle 已启用。
- Python 3.9/3.10 本机无解释器，仅 3.11/3.13 实测；install.ps1 版本校验已覆盖 3.9~3.13 判定。
- `cordis.patch.yml.installed` 是含本机真实路径的中间渲染产物（不入库为模板；是否需要纳入版本控制由上层安装流程决定）；模板本体可重复安装。
- 插件部署在 DSH_HOME 时 `inferRepoFromModule` 必然返回空并告警（设计行为）；已通过 bundle `config.repo: __REPO__` 和 env `PII_GUARD_REPO` 双保险确保 REPO 非空——安装时必须保证二者其一已配置。
