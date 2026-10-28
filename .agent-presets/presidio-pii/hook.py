"""DSH hook 适配层: 将 presidio_pii 引擎暴露为 before_llm / after_llm 两个钩子。

会话语义:
  - session_id 由 DSH 传入 (建议: conversation id), 未传入时按日期派生稳定 id,
    保证同一会话内的多轮请求共享同一张还原映射表。
  - before_llm 返回脱敏文本; after_llm 用同一 session_id 还原占位符。

状态传递: before_llm 的返回值若被 DSH 原样传给 after_llm (response 原文),
则 after_llm 只需 session_id 即可查库还原, 无需额外状态。
"""
from __future__ import annotations

import datetime as _dt
import hashlib
from pathlib import Path

from presidio_pii.engine import PresidioPIIEngine

_DEFAULT_DB = Path(__file__).resolve().parents[2] / ".pii_presidio_store" / "sessions.db"

_ENGINE: PresidioPIIEngine | None = None


def _get_engine(db_path: str | Path | None = None) -> PresidioPIIEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = PresidioPIIEngine(db_path=db_path or _DEFAULT_DB)
    return _ENGINE


def _session_id(conversation_id: str | None) -> str:
    if conversation_id:
        return hashlib.sha1(conversation_id.encode("utf-8")).hexdigest()[:12]
    today = _dt.date.today().isoformat()
    return "daily-" + hashlib.sha1(today.encode("utf-8")).hexdigest()[:8]


def before_llm(prompt: str, conversation_id: str | None = None,
               doc_id: str = "prompt", db_path: str | Path | None = None) -> str:
    """发送给 LLM 之前调用: 脱敏并登记映射。返回脱敏后的文本。"""
    engine = _get_engine(db_path)
    sid = _session_id(conversation_id)
    rd = engine.redact(prompt, sid, doc_id)
    return rd.text


def after_llm(response: str, conversation_id: str | None = None,
              doc_id: str = "prompt", db_path: str | Path | None = None) -> str:
    """LLM 响应返回后调用: 将占位符还原为原始 PII。"""
    engine = _get_engine(db_path)
    sid = _session_id(conversation_id)
    rs = engine.restore(response, sid, doc_id)
    return rs.text
