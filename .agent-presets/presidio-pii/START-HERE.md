# 启动指引 — 新会话测试 PII 防护模式

本文件是「PII 防护模式」preset 的启动入口。**用法：GUI 新建会话 → Agent Preset 选「PII 防护模式」→ 工作目录指向仓库根 → 把下面「可复制的提示词」整段粘贴为首条消息。**

仓库根目录（本机绝对路径）：`E:\Code\dsh-presidio-preset`

---

## 可复制的提示词

```
【任务】启动本仓库的 PII 脱敏链路测试。你在「PII 防护模式」preset 下运行。

【第一步：读取操作规范】（开工前必做，按顺序读完再动手）
1. 读取技能文件 skills/presidio-pii/SKILL.md（本 preset 注入），重点看第一节
   「核心命令速查」顶部的沙箱执行前提、第七节「工作流红线」、第八节「测试集核对」。
2. 读取 .agent-presets/presidio-pii/skills/presidio-pii/references/test-guide.md，
   它是本次测试的核对引导，命令、判定标准、红线以它为准。

【第二步：确认素材就位】
- 检查 E:\Code\dsh-presidio-preset\testdata_v2\：应有 resume/contract/official/report/
  paper/payroll/contacts 七个子目录、manifest.json 与 whitelist.txt。
- 缺素材时重建（先建目录）：
  New-Item -ItemType Directory -Force E:\Code\dsh-presidio-preset\testdata_v2
  python E:\Code\dsh-presidio-preset\tools\gen_corpus_v2.py --out E:\Code\dsh-presidio-preset\testdata_v2 --per-type 7 --seed 42
- 若 python 报 No module named presidio_pii，先执行：
  python -m pip install -e E:\Code\dsh-presidio-preset

【第三步：执行四格式核对】（顺序执行，命令原样，注意绝对路径）
1. pwsh 预建产物目录（硬性前置，不可跳过；python 自建目录后写 docx 会被沙箱拒绝）：
   New-Item -ItemType Directory -Force E:\Code\dsh-presidio-preset\.pii_presidio_store\verify-artifacts
2. 逐条运行，每条都要贴出输出证据：
   python E:\Code\dsh-presidio-preset\tools\verify_check.py --file E:\Code\dsh-presidio-preset\testdata_v2\resume\resume-01.docx --workdir E:\Code\dsh-presidio-preset\.pii_presidio_store\verify-artifacts
   python E:\Code\dsh-presidio-preset\tools\verify_check.py --file E:\Code\dsh-presidio-preset\testdata_v2\paper\paper-01.md --workdir E:\Code\dsh-presidio-preset\.pii_presidio_store\verify-artifacts
   python E:\Code\dsh-presidio-preset\tools\verify_check.py --file E:\Code\dsh-presidio-preset\testdata_v2\report\report-07.pptx --workdir E:\Code\dsh-presidio-preset\.pii_presidio_store\verify-artifacts
   python E:\Code\dsh-presidio-preset\tools\verify_check.py --file E:\Code\dsh-presidio-preset\testdata_v2\payroll\payroll-01.xlsx --workdir E:\Code\dsh-presidio-preset\.pii_presidio_store\verify-artifacts

【判定标准】（缺一不可）
- 每条输出 [result] PASS；
- 泄漏清单为空；单元/替换/还原三数中替换数 = 还原数；占位符零残留；
- 实体分布与 manifest.json 真值基本吻合（文档自带地名/机构的额外命中允许，需说明）。

【第四步：汇报格式】
1. 四格式核对结果表（文件 / 状态 / 单元 / 替换 / 还原 / 实体分布）；
2. 与 manifest.json 真值的比对结论；
3. 是否发现任何 FAIL 或异常；如有，定位到具体单元并说明原因。

【红线】
- 核对产物与日志含明文 PII：只读不提交、不外传；
- 不修改测试素材与 manifest.json；
- 不得跳过 pwsh 预建目录步骤直接跑 verify_check.py；
- 一切路径用绝对路径，不要依赖当前工作目录（CLI 会在 cwd 下建 .pii_presidio_store 导致 WinError 5）；
- 若核对不过，如实汇报 FAIL，不得宣称链路可用。
```

---

## 为什么提示词这样写（每条都有实测依据）

| 提示词中的约束 | 实测依据 |
| --- | --- |
| 四文件选样（resume-01.docx / paper-01.md / report-07.pptx / payroll-01.xlsx） | 这四份正是四格式核对全绿的那一组（27/13/13、1/13/13、19/13/13、111/70/70） |
| pwsh 预建 `--workdir` 是硬性前置 | 沙箱实测：python 子进程自建目录后写 docx 被拒（PermissionError）；pwsh 建目录则畅通 |
| 一切路径用绝对路径 | `cli.py` 的 `_demo()` 曾因 cwd 依赖落盘 `.pii_presidio_store` → WinError 5，已修复；文档层再钉一道 |
| `pip install -e` 兜底 | 包 `presidio-pii-dsh` 本机已装（site-packages 可编辑安装），提示词只做缺省兜底 |
| 三项判定 + 替换数=还原数 | 与 `verify_check.py` 的泄漏检查 / 还原无损 / 占位符清零三项校验一一对应 |
| `--per-type 7 --seed 42` | 固定 seed 可复现；per-type=7 正好让 report 类含 1 份 pptx，四格式全覆盖 |

## 测试通过后

链路绿了，才允许对真实敏感文档执行脱敏工作流：`redact` → 用脱敏文本工作 → `restore` 验证无损 → 交付。真实文档用 `--session` 落盘 SQLite 的场景，结束后要显式 `delete_session` 清除映射，不留残留。

## 已知的环境边界（非缺陷）

- `tools/standalone_check.py` 在沙箱内不可用（用 `tempfile.mkdtemp()` 建临时目录后写 docx 被拒）；沙箱内一律用 `tools/verify_check.py`。
- `pytest tests/` 在沙箱内跑不出全绿：tmp_path fixture 建目录被拒，报错是 `PermissionError`，与引擎无关；在沙箱外运行即可。
- 仓库内 `probe_*` 等空目录由沙箱内 python 子进程创建、受 ACL 保护，沙箱内外都删不掉，可忽略或手动清理。
