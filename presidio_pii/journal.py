"""结构化 JSONL 会话日志。

每行一条 JSON 记录, 记录脱敏/还原全流程中发出与接收的内容:
  {"ts": 1769...113, "event": "before_llm", "conversation_id": "...",
   "raw": "原始输入", "transformed": "脱敏后文本", "n_replaced": 3, ...}

隐私说明: 日志含原始 PII 明文, 仅落盘本地 `.pii_presidio_store/`
(已被 .gitignore 排除), 勿提交或同步到外部。
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path


class JsonlJournal:
    """追加式 JSONL 日志。每行一个完整 JSON 对象, 可用 jq/逐行 json.loads 消费。"""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: str, **fields) -> dict:
        rec = {
            "ts": round(time.time(), 3),
            "iso": datetime.now().isoformat(timespec="seconds"),
            "event": event,
        }
        rec.update(fields)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return rec

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out
