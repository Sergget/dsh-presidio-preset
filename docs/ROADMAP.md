# 开发计划备忘

记录已定方向与待办事项，避免决策丢失。

## 1. 当前基线（v0.1，已完成）

- 规则识别 + 可选 jieba 分词（`nr` 人名 / `ns` 地名 / 词边界对齐）
- 白名单：`--whitelist FILE` / `--keep TERM` / 环境变量 `PII_DSH_WHITELIST`
- 合成测试语料：`tools/gen_test_corpus.py` + `tools/eval_corpus.py`
- 基线指标（12 份合成文档，155 条真值）：

| 类型 | 召回 |
|---|---|
| PERSON / LOCATION / ID / PHONE / EMAIL / CREDIT | 100% |
| ORGANIZATION | 98.8% |
| 公司/单位简称（hard） | 95.8% |

## 2. NER 模型分档（待实施）

目标：补足「人名出现在无标点、无引导词的上下文」时的召回缺口。

| 档位 | 代表模型 | 参数 | 体积(int8) | 常驻内存 | 单段延迟 | 定位 |
|---|---|---|---|---|---|---|
| `none` | 规则 + jieba | — | 0 | ~50MB | 0.5–2ms | **默认** |
| `tiny` | `ckiplab/albert-tiny-chinese-ner` 一类 | ~4M | 5–15MB | ~50MB | 3–10ms | CI / 低配 / 离线 |
| `base` | `bert-base-chinese` 微调 NER | 102M | 100–120MB | ~500MB | 30–80ms | 推荐启用 |

硬件结论：**无需 GPU**。CPU 推理即可；M3 Air 上 base 模型 13KB 文档约 1.4s，prompt 级毫秒。真正成本是 `onnxruntime` 依赖（~15MB）与首次模型加载（~300ms）。

### 为什么 tiny 不作为默认

- 域偏移：公开 tiny NER 多在 MSRA/新闻语料训练，政务公文句式泛化差；参数量小，跨域退化快
- 行为不确定性：模型误报不可追溯，规则误报可定位；隐私工具里「结果随模型版本漂移」比慢几毫秒更难处理
- 省下的资源在本场景不是瓶颈（体积 15MB vs 120MB，延迟都是毫秒级）

### tiny 的价值（保留理由）

1. CI 集成测试：不拉 110MB 模型即可验证 NER 管线（下载/加载/滑窗/合并）
2. 低配与内网：8GB 以下内存、无 AVX2、完全离线环境
3. 基线对照：量化「多花 100MB 换多少召回」

## 3. 架构草案

```
presidio_pii/ner/
├── registry.py      # 模型清单（随包分发的静态 JSON，不含模型本体）
├── downloader.py    # 显式下载 + sha256 校验 + 断点续传
├── runtime.py       # onnxruntime 会话：懒加载、常驻、CoreML/CPU EP
└── backend.py       # detect(text) -> [(start, end, type, score)]
```

- 清单字段：`id / params / size_mb / url / sha256 / license / labels / quality`
- 缓存：`~/.cache/presidio_pii/models/<id>/`，**不自动下载**
- 依赖：`[project.optional-dependencies] ner = ["onnxruntime>=1.17", "tokenizers>=0.15"]`
- 合并：NER 结果作为候选与规则结果并集，走现有「长实体优先」裁决；加两道闸——置信度阈值（≥0.7）、命中文本不得是词典常用词

CLI 形态：

```bash
presidio-pii models list
presidio-pii models download base
presidio-pii models remove base
presidio-pii redact 报告.docx --ner base      # 本次启用
presidio-pii redact 报告.docx --ner auto      # 用已下载的最高档
```

## 4. 分阶段

| 阶段 | 内容 | 完成标准 |
|---|---|---|
| P0 | 规则 + 分词 + 白名单 + 合成语料评估 | 已完成 |
| P1 | NER 管线骨架 + tiny 接入（假 backend 先行） | CI 可跑通全链路，默认不启用 |
| P2 | 人工真值集（30–50 句）评估 tiny vs base | 输出增量召回 / 增量误报对比 |
| P3 | base 接入 + `models` 子命令 + 文档 | 默认仍为 none，需显式开启 |

## 5. 决策门槛

用真值集（人工标注 PERSON / LOCATION / ORGANIZATION）跑三套配置：

| 配置 | 关注 |
|---|---|
| 规则 + jieba | 基线 |
| + tiny | 增量召回 vs 新增误报 |
| + base | 增量召回 vs 新增误报 |

判定：**每多识别一个真名，是否值得多一个误报**。tiny 若为 1:3 而 base 为 1:0.3，tiny 只保留在 CI。

## 6. 风险

- **许可证**：清单中 `license` 必填；CC-BY-NC 类模型不得用于商用
- **模型漂移**：升级模型必须重跑真值集，指标不得回退
- **滑窗边界**：512 token / stride 64，跨段实体需拼接去重，测试必须覆盖「实体跨段」
- **依赖体积**：`onnxruntime` + tokenizers 约 30–50MB，仅在启用 NER 时安装
