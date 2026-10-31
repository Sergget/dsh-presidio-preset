# Presidio PII Redactor for DeepSeek Harness

[English](README.md) | **简体中文**

面向 DeepSeek Harness (DSH) 的本地化、轻量、可逆 PII（个人可识别信息）脱敏与还原中间件。借鉴 Microsoft Presidio 的模块化架构，全程离线运行于 CPU，不依赖任何重型 ML 组件（无需 spaCy/PyTorch），依靠优化的正则表达式、校验位算法与词典查表完成识别。

## 特性

- **多实体识别**：中文人名、身份证号（18 位含校验位、15 位旧版）、手机与座机号、邮箱、统一社会信用代码、银行卡（Luhn 校验）、护照、车牌号、IP/MAC 地址、省/市/县级行政区（`LOCATION`）、组织机构（`ORGANIZATION`）以及职位（`JOB_TITLE`）。
- **写法容错**：全角数字字母、数字内插值（`138 0013 8000`）、换行截断的证件号、带空格的姓名，识别前统一归一化，非标准写法同样能命中，且还原仍映射回原文。
- **词边界过滤**：每个命中都必须落在词边界上，词内片段一律丢弃（`内容要求` 里的 `容要求`、`所有部门` 里的 `所有部`、`政协委员` 里的 `委员`）。装上可选的 jieba 分词后，候选还须与分词边界对齐并符合词性（人名 `nr`、地名 `ns`），几乎消除误报。
- **可逆脱敏**：用抗碰撞的 Unicode 占位符替换敏感数据（如 `⟦PII:ID_NUMBER:0001⟧`）。
- **SQLite 会话映射库**：按会话记录映射关系，存于本地轻量 SQLite 数据库，保证 LLM 返回后文本可 100% 无损还原。
- **Office 文档支持**：可接入 `.docx`、`.pptx`、`.xlsx` 与纯文本。
- **格式覆盖**：可脱敏/还原 `.docx`（段落、表格、页眉页脚、文本框、批注、修订、脚注）、`.xlsx`（单元格与批注）、`.pptx`（文本框、表格、备注），以及 `.txt`、`.md`、`.csv`、`.json`、`.xml`、`.html`、`.eml`、`.rtf`。`.pdf`、`.doc`、`.xls` 为**只读检测**——可扫描识别但不能写回。
- **白名单**：指定关键词不替换——CLI 用 `--whitelist FILE`（每行一个词）或 `--keep TERM`，DSH preset 用 `PII_DSH_WHITELIST`。与白名单区域重叠的实体一律保留。

## 快速开始

```bash
cd E:\Coding\dsh-presidio-preset
pip install -e .
pip install -e ".[segment]"   # 可选: jieba 分词, 精度显著提升

# 运行往返演示
python -m presidio_pii.cli --demo

# 脱敏文档 (txt/md/docx/xlsx/pptx)
python -m presidio_pii.cli redact report.docx
# -> report-redacted/report.docx
#    report-redacted/report.docx.mapping.csv   (占位符 <-> 原文)
#    report-redacted/report.docx.session.csv   (session id / 路径)

# 简写: 直接给文件路径等价于 redact
python -m presidio_pii.cli report.docx

# -v 显示阶段进度与逐单元命中; -d 指定输出目录
python -m presidio_pii.cli redact report.docx -v -d out/

# 还原 (从文件旁的 CSV 读取映射, 不依赖映射库)
python -m presidio_pii.cli restore report-redacted/report.docx
# -> report-restored/report.docx
```

输出布局: 脱敏产物落在源文件同级的 `<文件名>-redacted/`, 还原产物落在 `<文件名>-restored/`。
`-o` 写入显式文件路径, 与 `-d` 互斥。裸脚本运行时, 脱敏对应关系存放在
`<文件名>.mapping.csv` (`idx,ptype,placeholder,original`, UTF-8 带 BOM, 可直接用 Excel 打开),
整个脱敏目录拷到别的机器也能还原; `.pii_presidio_store/` 下的 SQLite 映射库只是兜底。
CLI 默认使用内存映射库 (不逐条写盘); 需要让同一会话跨多个文件时, 加 `--session` 走持久化
SQLite 映射库。DSH preset 使用自己的落盘格式, 不受影响。

## 测试

```bash
pip install -e ".[dev]"
pytest tests/ -v                          # 23 个回归用例

# 无 DSH 检测真实文档 (泄漏检查 + 还原无损 + 占位符清零, JSON 报告)
python tools/standalone_check.py 报告.docx 名单.xlsx

# 无 DSH 模拟多轮对话, 记录结构化发出/接收日志 (JSONL)
python tools/dsh_sim.py --turn "张伟的身份证是110101199003077890,帮我查"

# 生成合成测试语料 (虚构单位/公司/人名/证件号), 切分成多份小文档
python tools/gen_test_corpus.py --base 项目建议书-redacted/项目建议书.docx --out testdata/ --parts 12

# 按真值清单评估召回与误报
python tools/eval_corpus.py --dir testdata/

# 多类型语料: 简历/合同/公文/报告/文献/工资表/通讯录 (共 84 份)
python tools/gen_corpus_v2.py --out testdata_v2 --per-type 12
python tools/eval_corpus.py --dir testdata_v2/
```

详见 [tools/README.md](tools/README.md)。

## 架构

- **`presidio_pii/engine.py`**：核心脱敏与还原流水线 + 优先级重叠消解。
- **`presidio_pii/chinese_recognizers.py`**：中文 PII 识别器（兼容 Presidio API）。
- **`presidio_pii/db.py`**：SQLite 会话映射存储。
- **`presidio_pii/documents.py`**：txt/docx/xlsx/pptx 的文本单元抽取与回写。
- **`presidio_pii/cli.py`**：命令行接口。
- **`tools/`**：无 DSH 文档检测、DSH 流程模拟、合成语料生成与评估。
- **`docs/ROADMAP.md`**：开发计划，含可选的 NER 模型分档。
- **`.agent-presets/presidio-pii/`**：DeepSeek Harness (DSH) agent preset 集成。
