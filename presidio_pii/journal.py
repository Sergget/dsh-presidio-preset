"""结构化 JSONL 会话日志（不含明文）。

每行一条 JSON 记录，只保留排查所需的**元数据**：
时间、事件、实体类型与数量、内容指纹哈希、跳过原因等。

隐私说明：**不记录原文、脱敏文本或还原后文本**。内容指纹是单向 SHA256
（只取前 16 位），占位符本身不落日志；两者都不足以还原原文 —— 原文只存在于
映射库（`.pii_presidio_store/sessions.db`，已被 .gitignore 排除）。

轮转：超过 `max_bytes`（默认 10 MB）时，当前文件改名为 `<name>.1`（覆盖旧
`.1`），随后从空文件继续写。单条记录超限时先轮转，因此当前文件最大约为
`max_bytes + 单条记录大小`。`max_bytes <= 0` 表示不限额。
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime
from pathlib import Path

DEFAULT_MAX_BYTES = 10 * 1024 * 1024


class JsonlJournal:
    """追加式 JSONL 日志。每行一个完整 JSON 对象, 可用 jq/逐行 json.loads 消费。"""

    def __init__(self, path: str | Path, max_bytes: int = DEFAULT_MAX_BYTES):
        self.path = Path(path)
        self.max_bytes = max(0, int(max_bytes))
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _rotate_if_needed(self, incoming: int) -> None:
        if self.max_bytes <= 0:
            return
        try:
            size = self.path.stat().st_size
        except OSError:
            return
        if size + incoming <= self.max_bytes:
            return
        backup = self.path.with_name(self.path.name + ".1")
        try:
            backup.unlink(missing_ok=True)
            os.replace(self.path, backup)
        except OSError:
            # 轮转失败时不阻塞写入; 宁可继续追加也不丢记录
            pass

    def record(self, event: str, **fields) -> dict:
        rec = {
            "ts": round(time.time(), 3),
            "iso": datetime.now().isoformat(timespec="seconds"),
            "event": event,
        }
        rec.update(fields)
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        self._rotate_if_needed(len(line.encode("utf-8")))
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line)
        return rec

    def read_all(self) -> list[dict]:
        """读取当前日志文件（不含已轮转的 `.1`）。"""
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out
