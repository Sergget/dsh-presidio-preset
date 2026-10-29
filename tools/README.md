# 测试工具

两个层次的测试工具, 均不依赖 DSH 即可运行; 真实 DSH 接入时复用同一套日志格式。

## 1. 无 DSH 测试真实文档 — `standalone_check.py`

对任意真实文档执行完整流程并校验:

```
抽取文本单元 → redact → 写出脱敏文档 → 模拟 LLM (原样返回) → restore → 逐单元与原文比对
```

```bash
python tools/standalone_check.py 报告.docx 名单.xlsx 备注.txt
python tools/standalone_check.py 报告.docx --report out.json --keep   # 保留产物
```

支持格式: `txt` / `md` / `docx` / `xlsx` / `pptx`

**三项自动校验**:
1. **泄漏检查** — 已识别的 PII 明文不得出现在脱敏产物中
2. **还原无损** — 还原后每个文本单元与原文完全一致
3. **占位符清零** — 还原产物不得残留 `⟦PII:...⟧`

**输出**: 控制台摘要表 + JSON 报告:

```json
{
  "all_pass": true,
  "results": [{
    "file": "名单.xlsx", "status": "PASS",
    "n_units": 6, "n_replaced": 3, "n_restored": 3,
    "entity_counts": {"PERSON": 1, "ID_NUMBER": 1, "PHONE_NUMBER": 1},
    "leaked_pii": [],
    "unit_results": [{"unit": "Sheet!A1", "roundtrip_equal": true,
                      "no_placeholder_left": true}]
  }]
}
```

退出码: 全部通过 `0`, 任一失败 `1` (可用于 CI)。

> 注意: `--keep` 产物与映射库含明文 PII, 仅限本地; 默认产物在临时目录自动清理。

## 2. DSH 流程模拟器 — `dsh_sim.py`

在无 DSH 环境下模拟真实多轮对话, 记录**结构化的发出/接收日志**:

```bash
python tools/dsh_sim.py \
  --turn "张伟的身份证是110101199003077890,帮我查一下" \
  --turn "再查一下李明的手机号 13800138000" \
  --conversation-id demo-001
```

每轮流程: `用户输入 → before_llm 脱敏(发出) → mock LLM 回复(接收) → after_llm 还原`。
mock LLM 会像真实模型一样在回复中原样引用占位符, 因此能验证多轮引用同一实体的还原正确性。

### 结构化日志格式 (JSONL, 每行一条)

流程日志 `.pii_presidio_store/sim_<conversation_id>.jsonl`, 每轮两条:

```jsonc
// outgoing: 发给 LLM 的内容 (脱敏后)
{"ts": 1793175321.68, "iso": "2026-10-28T16:15:21", "event": "turn",
 "turn_no": 1, "stage": "outgoing", "conversation_id": "demo-001",
 "raw_prompt": "用户原文", "sent_to_llm": "⟦PII:PERSON:0001⟧的身份证是⟦PII:ID_NUMBER:0001⟧...",
 "n_redacted": 2}

// incoming: LLM 返回 + 还原结果
{"event": "turn", "turn_no": 1, "stage": "incoming", "conversation_id": "demo-001",
 "llm_response": "[模拟LLM] ...⟦PII:PERSON:0001⟧...",
 "restored": "[模拟LLM] ...张伟...", "n_restored": 2,
 "n_unrestored": 0, "placeholders_left": 0}
```

### 真实 DSH 接入时的日志

引擎级日志 `hook_log.jsonl` 由 `presidio_pii.hooks` 自动记录, 无需额外接线:

| 字段 | 说明 |
|------|------|
| `event` | `before_llm` / `after_llm` |
| `conversation_id` / `session_id` | 会话标识与派生的存储会话 |
| `doc_id` | 轮次/文档标识 |
| `raw` | 原始内容 (发送前 prompt / LLM 返回) |
| `transformed` | 转换后内容 (脱敏文本 / 还原文本) |
| `n_replaced` / `n_restored` / `n_unrestored` | 数量统计 |
| `entities` | 实体类型分布 (仅 before_llm) |

环境变量: `PII_DSH_DB_PATH` / `PII_DSH_LOG_PATH` (设为 `0` 关闭日志)。

**隐私警告**: 两类日志都含 PII 明文, 全部落盘本地 `.pii_presidio_store/`
(已 gitignore), 勿提交仓库或同步到外部。

## 3. 单元/回归测试

```bash
pip install -e ".[dev]"
pytest tests/ -v        # 用例: 识别边界 / round-trip / 日志 / 模拟流程 / 白名单
```

## 4. 合成测试语料 — `gen_test_corpus.py`

把虚构的单位（国家级/省部级/市级/县级）、公司、公司简称、人名、地址、身份证号、
手机号、邮箱、统一社会信用代码混入一份基础 docx，切分成多份小文档，并输出真值清单。

```bash
python tools/gen_test_corpus.py \
  --base 项目建议书-redacted/项目建议书.docx \
  --mapping 项目建议书-redacted/项目建议书.docx.mapping.csv \
  --out testdata/ --parts 12 --seed 42
```

- `--mapping` 用于把基础文档里的 `⟦PII:...⟧` 还原成（已脱敏的）原文；不传则保留占位符
- 固定 `--seed` 保证可复现；身份证号按 GB/T 11643 生成有效校验位
- 产出：`part-01.docx …`、`manifest.json`（每条真值含 `type` 与 `hard` 标记）、`whitelist.txt`
- 公司/单位简称（如「智数科技」「省数据局」）标记为 `hard`，单独统计

> `testdata/` 已 gitignore：产物含基础文档内容，只在本地使用。

## 5. 召回/误报评估 — `eval_corpus.py`

对合成语料跑一遍识别，按真值清单统计召回与额外命中。兼容 v1（`parts`）与 v2（`docs`）两种 manifest。

```bash
python tools/eval_corpus.py --dir testdata/
python tools/eval_corpus.py --dir testdata_v2/ --whitelist testdata_v2/whitelist.txt
python tools/eval_corpus.py --dir testdata_v2/ --json testdata_v2/report.json
```

- 召回按类型统计；真值被识别区间覆盖 ≥80% 即计为命中（允许地址被拆成省/市/区/街道多段）
- `额外命中` 是与所有真值区间都不重叠的识别结果，可能是文档自带的地名/机构，需人工判断
- `简称(hard)` 单列：简称通常不在任何词典里，是规则方案的已知短板

## 6. 多类型语料 v2 — `gen_corpus_v2.py`

覆盖简历 / 合同 / 公文 / 报告 / 文献 / 工资表 / 通讯录 7 类，每类默认 12 份，共 84 份。

```bash
python tools/gen_corpus_v2.py --out testdata_v2 --per-type 12 --seed 42
```

- 格式按类型取自然载体：docx（简历/合同/公文/报告）、pptx（报告汇报版）、
  md（文献）、xlsx（工资表/通讯录）、docx 表格（通讯录）
- 真值 2400+ 条，含字段名（`姓名`/`身份证号`/`岗位`…）与 `hard` 标记
- 身份证校验位有效、银行卡通过 Luhn；全部为虚构数据
- `manifest.json` 记录每份文档的类型、格式与真值；`whitelist.txt` 为白名单示例
- 基础版式由代码生成（`docs/SOURCES.md` 记录了模板下载尝试与不可用原因）

