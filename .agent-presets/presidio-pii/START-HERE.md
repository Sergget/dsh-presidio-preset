# 启动指引 — 新会话测试 PII 防护模式

本文件是「PII 防护模式」preset 的启动入口。

**用法**：GUI 新建会话 → Agent Preset 选「PII 防护模式」→ 工作目录指向仓库根
→ 把下面「可复制的提示词」整段粘贴为首条消息。

仓库根目录（本机绝对路径）：`E:\Code\dsh-presidio-preset`

> **若 preset 选择器里没有「PII 防护模式」或显示加载失败**：本提示词第一段自带降级路径
> ——在没有 preset 的普通会话里同样能跑通全部核对（核对命令不依赖 preset，只依赖
> Python 引擎与测试素材）。先把链路证据拿到，preset 激活问题另案处理。

---

## 可复制的提示词

```
【任务】在本仓库执行 PII 脱敏链路的端到端核对，并给出带证据的结论。
仓库根目录：E:\Code\dsh-presidio-preset（下称 <REPO>）。所有命令用绝对路径，不要依赖当前工作目录。

【第零步：确认运行模式】
先判定你是否运行在「PII 防护模式」preset 下：
- 若你能加载 presidio-pii 技能（或环境提示已注入 PII 脱敏纪律）→ 记为「模式：PII 防护」。
- 若不能（preset 未启用/加载失败）→ 记为「模式：标准（降级）」并继续，不要中断。
两种模式下的核对命令完全相同；差异只在于你是否按 PII 纪律处理后续真实文档。

【第一步：读规范】（按顺序读完再动手）
1. 读 <REPO>\.agent-presets\presidio-pii\skills\presidio-pii\SKILL.md
   重点：第一节「核心命令速查」顶部的沙箱执行前提、第七节「工作流红线」、第八节「测试集核对」。
2. 读 <REPO>\.agent-presets\presidio-pii\skills\presidio-pii\references\test-guide.md
   它是本次核对的权威引导：命令、判定标准、红线以它为准。

【第二步：素材与工具自检】
逐项确认存在（缺任何一项就先补，不要跳过）：
- <REPO>\tools\verify_check.py          核对工具
- <REPO>\testdata_v2\manifest.json     真值清单
- <REPO>\testdata_v2\whitelist.txt     白名单
- 四份样本：
  testdata_v2\resume\resume-01.docx
  testdata_v2\paper\paper-01.md
  testdata_v2\report\report-07.pptx
  testdata_v2\payroll\payroll-01.xlsx
缺素材时重建（先建目录再生成）：
  New-Item -ItemType Directory -Force <REPO>\testdata_v2
  python <REPO>\tools\gen_corpus_v2.py --out <REPO>\testdata_v2 --per-type 7 --seed 42
若 python 报 No module named presidio_pii：
  python -m pip install -e <REPO>

【第三步：执行四格式核对】
硬性前置（不可跳过）：产物目录必须先用 pwsh 建好，python 子进程自建目录后写 docx 会被沙箱拒绝。
  New-Item -ItemType Directory -Force <REPO>\.pii_presidio_store\verify-artifacts

然后逐条运行，每条都要贴出完整输出：
  python <REPO>\tools\verify_check.py --file <REPO>\testdata_v2\resume\resume-01.docx --workdir <REPO>\.pii_presidio_store\verify-artifacts
  python <REPO>\tools\verify_check.py --file <REPO>\testdata_v2\paper\paper-01.md --workdir <REPO>\.pii_presidio_store\verify-artifacts
  python <REPO>\tools\verify_check.py --file <REPO>\testdata_v2\report\report-07.pptx --workdir <REPO>\.pii_presidio_store\verify-artifacts
  python <REPO>\tools\verify_check.py --file <REPO>\testdata_v2\payroll\payroll-01.xlsx --workdir <REPO>\.pii_presidio_store\verify-artifacts

【第四步：判定】（缺一不可）
对每份样本逐条核对：
a) 输出含 [result] PASS；
b) 泄漏清单为空（leaked_pii 无内容）；
c) 「单元/替换/还原」三数中，替换数 == 还原数；
d) 还原产物无 ⟦PII:...⟧ 残留。
任一条不满足即 FAIL，不得四舍五入写成通过。

【第五步：真值比对】
读 <REPO>\testdata_v2\manifest.json，对每份样本取对应条目的 entities（真值实体），
与第四步输出的「实体分布」比对：
- 真值中的类型是否都在实体分布里出现；
- 额外命中（真值没有但引擎识别出的）逐一列出并判断是否合理（文档自带的地名/机构属正常）。
把「真值命中 / 额外命中 / 缺失类型」三栏做成表。

【第六步：汇报格式】
1. 运行模式（PII 防护 / 标准降级）；
2. 四格式结果表：文件 | 状态 | 单元 | 替换 | 还原 | 实体分布；
3. 真值比对表：文件 | 真值命中 | 额外命中 | 缺失类型；
4. 结论：通过 / 未通过；未通过时定位到具体单元/类型并给出错误原文；
5. 若发现任何 FAIL，先读失败单元再下判断，不得只写「失败」。

【红线】
- 产物与日志含明文 PII：只读、不提交、不外传；全部落在 <REPO>\.pii_presidio_store\ 下；
- 不修改 testdata_v2 下的素材与 manifest.json；
- 不得跳过 pwsh 预建目录直接跑 verify_check.py；
- 一切路径用绝对路径（CLI 在 cwd 下建 .pii_presidio_store 会触发 WinError 5）；
- 核对不过就如实报 FAIL，不许宣称链路可用。
```

---

## 为什么这样写（每条都有实测依据）

| 约束 | 依据 |
| --- | --- |
| 四份样本固定为 resume-01/paper-01/report-07/payroll-01 | 这四份正是本机实测四格式全绿的一组（27/13/13、1/13/13、19/13/13、111/70/70） |
| pwsh 预建 `--workdir` 是硬性前置 | 沙箱实测：python 子进程自建目录后写 docx 被拒（PermissionError）；pwsh 建目录畅通 |
| 一切路径用绝对路径 | `cli.py` 的 cwd 依赖曾导致落盘 `.pii_presidio_store` → WinError 5（已修复，文档层再钉一道） |
| 替换数 == 还原数 | `verify_check.py` 每处脱敏都登记映射，还原应一一对应；不等即说明映射丢失 |
| `--per-type 7 --seed 42` | 固定 seed 可复现；per-type=7 正好让 report 类含 1 份 pptx，四格式全覆盖 |
| 零步先判定模式 | preset 若仍加载失败，核对命令不依赖 preset，仍可拿到链路证据（不阻塞） |

## 测试通过后

链路绿了才允许处理真实敏感文档：`redact` → 用脱敏文本工作 → `restore` 验证无损 → 交付。
真实文档若用 `--session` 落盘 SQLite，结束要显式 `delete_session` 清除映射。

## 已知环境边界（非缺陷）

- `tools/standalone_check.py` 在沙箱内不可用（`tempfile.mkdtemp()` 建目录后写 docx 被拒）；沙箱内一律用 `tools/verify_check.py`。
- `pytest tests/` 在沙箱内跑不出全绿：tmp_path fixture 建目录被拒，报 `PermissionError`，与引擎无关；沙箱外运行即可。
- 仓库内 `probe_*` 等空目录由沙箱内 python 子进程创建、受 ACL 保护，沙箱内外都删不掉，可忽略。
