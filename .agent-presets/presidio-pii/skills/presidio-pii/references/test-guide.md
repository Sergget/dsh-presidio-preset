# PII 防护模式 — 测试集与核对指南

本文档供 PII 防护模式内的 agent 使用：拿到含 PII 的任务时，先用本测试集验证脱敏/还原链路，再处理真实文档。**按本文件核对，不凭感觉下结论。**

## 一、测试素材（全部虚构，无真实 PII）

位置：仓库根目录 `testdata_v2/`（gitignore，不提交）。

| 素材 | 位置 | 内容 |
|------|------|------|
| 7 类文档 | `testdata_v2/<type>/<type>-NN.<ext>` | 简历/合同/公文(docx)、报告(docx+pptx)、文献(md)、工资表/通讯录(xlsx) |
| 真值清单 | `testdata_v2/manifest.json` | 每份文档的类型、格式与真值实体（`entities` 数组） |
| 白名单示例 | `testdata_v2/whitelist.txt` | 3 个关键词（国家数据局/智数科技/合肥市数据资源局） |

重建命令（素材被删或需换 seed 时）：

```powershell
New-Item -ItemType Directory -Force testdata_v2   # 若目录不存在
python tools/gen_corpus_v2.py --out testdata_v2 --per-type 7 --seed 42
```

生成器参数：`--per-type` 每类份数（默认 12，全量 84 份）；`--seed` 随机种子（固定可复现）。身份证校验位有效、银行卡通过 Luhn。

**核对文件选择**：四种格式各取一份即可覆盖格式矩阵——
`resume-01.docx`、`paper-01.md`、`report-07.pptx`、`payroll-01.xlsx`。

## 二、核对工具（沙箱友好版）

`tools/verify_check.py` —— 对单个文件执行 抽取→脱敏→模拟 LLM→还原→三项校验。

> **为什么不是 standalone_check.py**：原版用 `tempfile.mkdtemp()` 在临时目录写产物，DSH 沙箱内 python 子进程自建目录后写 docx 会被拒（PermissionError）。`verify_check.py` 要求产物目录由 pwsh 预创建，python 只写文件，沙箱内可用。**先建目录再跑，是硬性前置。**

### 核对流程（按序执行）

> 仓库根目录 = `E:\Code\dsh-presidio-preset`（下称 `<REPO>`）。**所有路径写绝对路径**，
> 不要用当前工作目录相对路径——模式内 agent 的 cwd 是用户项目目录，不是仓库。

```powershell
# 1) 预建产物目录（必须 pwsh 建，python 建会踩沙箱 ACL）
New-Item -ItemType Directory -Force E:\Code\dsh-presidio-preset\.pii_presidio_store\verify-artifacts

# 2) 批量核对（一次进程复用引擎，四格式 ~5s，比单条快 ~93%）
python E:\Code\dsh-presidio-preset\tools\verify_check.py --files `
  E:\Code\dsh-presidio-preset\testdata_v2\resume\resume-01.docx `
  E:\Code\dsh-presidio-preset\testdata_v2\paper\paper-01.md `
  E:\Code\dsh-presidio-preset\testdata_v2\report\report-07.pptx `
  E:\Code\dsh-presidio-preset\testdata_v2\payroll\payroll-01.xlsx `
  --workdir E:\Code\dsh-presidio-preset\.pii_presidio_store\verify-artifacts

# 单文件核对（等价）: --files 只传一个；restored 明文产物默认清理，--keep 保留
python E:\Code\dsh-presidio-preset\tools\verify_check.py --files E:\Code\dsh-presidio-preset\testdata_v2\resume\resume-01.docx --workdir E:\Code\dsh-presidio-preset\.pii_presidio_store\verify-artifacts
```

> 若 `python` 报 `No module named presidio_pii`，先执行
> `python -m pip install -e E:\Code\dsh-presidio-preset`（本机已安装，通常不需要）。

### 判定标准（三项全过才是 PASS）

1. **泄漏检查**：脱敏产物中不得出现任何已识别 PII 明文（`leaked_pii` 为空）。
2. **还原无损**：还原产物每个文本单元与原文完全一致（`roundtrip_equal` 全 true）。
3. **占位符清零**：还原产物无 `⟦PII:...⟧` 残留（`no_placeholder_left` 全 true）。

输出示例（PASS 形态）：

```
状态  PASS
  文件   : testdata_v2\resume\resume-01.docx
  单元/替换/还原: 27/13/13
  实体分布: {'PERSON': 2, 'PHONE_NUMBER': 1, ...}
```

`单元/替换/还原` 三数中替换数 = 还原数是预期（每处脱敏都应在还原时回来）；实体分布应与 manifest.json 真值基本吻合（允许差异：真值是生成时注入的，引擎可能多识别文档自带地名/机构，属正常，需人工判断）。

## 三、白名单核对

```powershell
# 白名单文件内容：国家数据局 / 智数科技 / 合肥市数据资源局
python -m presidio_pii.cli redact 测试文本.txt --whitelist testdata_v2\whitelist.txt
# 或环境变量
$env:PII_DSH_WHITELIST = (Resolve-Path testdata_v2\whitelist.txt).Path
```

命中白名单的区域不脱敏，重叠实体一并跳过。核对点：文本中「国家数据局」「智数科技」「合肥市数据资源局」保持原文，其余实体被脱敏。

## 四、红线

1. **产物与日志含明文 PII**：`*-redacted/`、`*.mapping.csv`、`.pii_presidio_store/`（含 verify-artifacts、hook_log.jsonl、*.db）全部 gitignore——**只读不提交、不外传、不写进 prompt 上下文外的地方**。
2. **先建目录再核对**：`verify_check.py` 的 `--workdir` 必须已存在（pwsh 创建），否则 PermissionError。
3. **核对不过不放行**：三项任一 FAIL 时，禁止把「引擎没问题」写进结论；先定位失败单元（输出里 `失败单元` 列表），再看是识别漏/误报还是格式回写问题。
4. **测试集可重建**：素材损坏时按第一节命令重建（固定 seed 保证可复现），不手改 manifest.json。
5. **truth.json 明文禁止**：`testdata_v2/truth.json` 含明文 PII 真值（仅供本地 `eval_corpus.py`）——**不得 read、不得引用其中文本**。真值比对只用 `manifest.json` 的 type/hash。
6. **本模式是自律工作流，不是强制机制**：preset 要求 agent 遵守 redact-first 纪律，但无法阻止模型直接 read/grep 源文件明文。**脱敏不可跳过仅对守规矩的 agent 成立**；源文件、truth.json、`.restored` 产物均为明文，模型按工具权限可读。

## 五、核对通过后的动作

链路验证绿了，才允许对真实敏感文档执行脱敏工作流（`redact` → 用脱敏文本工作 → `restore` 验证无损 → 交付）。真实文档处理完成后，`--session` 落盘 SQLite 的场景要显式 `delete_session`，不留映射库残留。
