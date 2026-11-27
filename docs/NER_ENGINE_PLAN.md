# PII 识别引擎替换调研与计划

> 2026-11-27 · 背景：现有 Node 正则+姓氏启发式识别器（`node_pii/recognizers.mjs`）在政府公文场景经四轮
> stopword/边界修补后，误报仍有残余，且漏报（句中机构名漏识别）结构性存在。正则/词典方案天花板已到。
> jieba 分词（`boundaries`/`posTokens`）当前恒为 null 未启用，即使启用，词性标注对"成稿/安排"这类
> 词例也无能为力。故调研其他引擎路线。

## 一、候选路线对比

### 路线 A：ONNX Runtime + 中文 BERT/RoBERTa NER（token-classification）★推荐主线

**原理**：本地跑 token-classification 模型（BERT-base 12 层），逐 token 分类出 PER/ORG/LOC 等实体，
上下文感知，天然解决"成稿（动词后非人名）vs 高峰（真名）"这类启发式无法区分的案例。

**关键事实（已核实）**：

| 项 | 结论 |
|---|---|
| 运行时 | `onnxruntime-node`（微软官方 npm 包，Windows x64 原生 .node 插件，直接可用）；或 `@huggingface/transformers`（transformers.js v3，内置 onnxruntime-node + tokenizer + pipeline，零胶水代码） |
| 候选模型 1 | `Xenova/bert-base-chinese-ner`（= ckiplab/bert-base-chinese-ner 的 ONNX 转换，Transformers.js 即开即用）：quantized **98.2 MB**、fp16 194 MB、fp32 388 MB（HEAD 实测）。缺点：ckiplab 训练语料偏台湾中文 |
| 候选模型 2 | `uer/roberta-base-finetuned-cluener2020-chinese`（CLUENER2020 微调，简体大陆语料，更贴公文场景）：仓库**无现成 ONNX**（只有 pytorch/tf/flax），需一次性用 Python `optimum-cli export onnx` 导出并量化（~100 MB quantized），tokenizer/vocab.txt 仓库自带 |
| 标签体系 | CLUENER2020 共 10 类：name(人名)/organization(组织)/government(政府)/company(公司)/address(地址)/position(职位)/book/game/movie/scene。映射到本项目：name→PERSON，organization+government+company→ORGANIZATION，address→LOCATION，position→JOB_TITLE；book/game/movie/scene 忽略 |
| 准确率 | CLUENER2020 SOTA 榜 BERT-base 级别 F1 ≈ 79-80%（细粒度 10 类较难）；只取 PER/ORG/LOC 三大类的实际表现高于整体 F1。显著优于启发式：CLUENER 训练数据本身已学会"成稿"不是人名 |
| 延迟 | CPU（Windows 无 GPU 要求）BERT-base 128 token 输入量化后约 100-300ms/次，段级调用足够（guard 的 post-execute 是逐工具结果调用，单次文本通常 <2000 字） |

**集成方式**（与现有架构贴合）：
- 新增 `node_pii/ner_model/`（模型文件放 dsh_home data 目录，不入仓库）+ `ner.mjs`：加载 ONNX，
  实现 bert tokenizer（transformers.js 自带 `AutoTokenizer`）+ token 分类 + BIO 解码。
- `recognizers.mjs` 加一个 `makeNerRecognizer()`：返回与现识别器同构的 `{ entities(text) }`，
  在 engine 注册为 PERSON/ORGANIZATION/LOCATION 的**优先识别器**；现有正则识别器降级为
  fallback（模型未部署/加载失败时自动回退，failOpen 语义不变）。
- 强类型 PII（ID_CARD/PHONE/BANK_CARD/EMAIL 等）**保持正则**——正则在这类上零误报零漏报，不需要模型。
- whitelist_path / PERSON_STOPWORDS 机制保留：作为模型误报的最终兜底（模型也会犯错，
  双保险叠加成本为零）。

**成本**：新增依赖 transformers.js（~20MB node_modules）；模型文件一次性下载 ~100-200MB；
首次加载 1-3s（可 lazy load）。

### 路线 B：模型仅用于 NER 三类，正则管强类型（= 路线 A 的精确表述）

实际上 A 即 B：把"换引擎"限制在 PERSON/ORG/LOCATION/JOB_TITLE 四个模糊类，强类型不动。
这是推荐落地形态，单列以强调**不必全量替换**。

### 路线 C：领域词典 + 后缀树（现方案增强版）

维护政府机构词典（民政/教体/检察系统全名录）+ 人名姓氏白名单 + 上下文窗口打分。
- 优点：零新依赖、零模型下载、延迟微秒级。
- 缺点：天花板明显——词典外的机构（新设/简称/粘连）依旧漏，普通词误命中依旧需要逐词打补丁；
  本轮四轮修补已证明这是无底洞。**仅作为路线 A 不可用时的退路**。

### 路线 D：调用本地 LLM（DSH 已有模型）做 NER

- 优点：无新增部署。
- 缺点：每次工具输出都要过一次 LLM，延迟秒级；结果不稳定（同一文本不同次输出可能不同）；
  占位符编号机制要求确定性识别。**否决**。

### 路线 E：API NER 服务（腾讯云/阿里云 NER）

- 缺点：文本需出本机，违背 presidio-pii 插件"本地脱敏"的核心安全前提（待脱敏文本可能含明文 PII）。
  **否决**。

## 二、推荐决策

**路线 A/B（同一方案）**：transformers.js + 中文 NER ONNX 模型做 PERSON/ORGANIZATION/LOCATION/JOB_TITLE，
正则保留强类型 PII + fallback，whitelist/stopword 保留兜底。

模型选型顺序：
1. 首选导出 `uer/roberta-base-finetuned-cluener2020-chinese` 的 quantized ONNX（简体大陆公文语料最匹配；
   导出是一次性 Python 步骤，产物放 data 目录）。
2. 若不愿做导出步骤，直接用 `Xenova/bert-base-chinese-ner`（98MB 下载即用，但台湾语料，
   简体政府机构识别需实测验证）。

## 三、实施计划

| 阶段 | 内容 | 验收 |
|---|---|---|
| P1 | 装 `@huggingface/transformers`（transformers.js v3）；写 `ner.mjs`：加载模型→tokenize→推理→BIO 解码→实体列表 | probe 脚本对 f0ac0bab 会话 444 占位符语料重放：误命中词（成稿/成长/司法/月举办/致全市台球室等）0 命中，真实实体（杨祺/市民政局/市公安局/宣城市人民检察院/广德市法院）全部命中 |
| P2 | `recognizers.mjs` 增 `makeNerRecognizer` 注册为优先；模型缺失/失败自动回退现有正则 | 现有全部回归保持通过：test_fixes 13/13、test_mask_fix 13/13、guard-fs-tools 33/33、plugin_unified 40/40 |
| P3 | 配置项 `nerEnabled`/`nerModelPath`（guard-settings.json），默认关闭、显式开启 | 设置页可切换；关闭时行为与当前完全一致 |
| P4 | 延迟与体积实测（含首次加载），写 README 部署说明 | 单次工具结果 <500ms；说明含模型导出/下载/放置路径 |
| P5（可选） | 用 DSH 会话历史积累的误报/漏报样本做小规模微调语料，二次微调模型（Python 侧，非本机必须） | 误报率进一步下降 |

## 四、风险与备注

- CLUENER 的 address 标注"标记到最细"，LOCATION 召回可能比现正则更碎（如"宁国""郎溪"按
  address 独立标记）——对脱敏场景反而有利（多脱不漏）。
- government 与 organization/company 边界在模型里有混淆（软件学报 2021 指出 CLUENER 内部
  org/gov/company 混淆度高）——本项目三者同映射 ORGANIZATION，不受影响。
- 模型文件不入 git 仓库（体积），放 `E:\Coding\dsh_home\data\presidio-pii\models\`，
  config 用路径引用。
- 证据等级说明：模型 F1 数字来自 CLUENER2020 leaderboard 与论文（arXiv:2001.04351），延迟为
  BERT-base CPU 量化模型的常规量级估计，P4 实测后修正。

## 五、参考

- CLUENER2020 数据集与基准：https://github.com/CLUEbenchmark/CLUENER2020 、arXiv:2001.04351
- uer/roberta-base-finetuned-cluener2020-chinese：https://huggingface.co/uer/roberta-base-finetuned-cluener2020-chinese
- Xenova/bert-base-chinese-ner（现成 ONNX）：https://huggingface.co/Xenova/bert-base-chinese-ner
- transformers.js（token-classification pipeline / AutoTokenizer）：https://huggingface.co/docs/transformers.js
- 本地 ONNX NER 实践参考：https://www.cnblogs.com/yangykaifa/p/19365604 、https://cloud.tencent.com/developer/article/2625158
