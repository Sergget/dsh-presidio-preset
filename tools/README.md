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
pytest tests/ -v        # 23 个用例: 识别边界 / round-trip / 日志 / 模拟流程
```
