"""DSH 钩子实现: before_llm / after_llm + 结构化流程日志。

会话语义:
  - session_id 由 conversation_id 派生 (稳定哈希), 同一会话多轮共享还原映射表;
    未传入时按日期派生, 同一天内共享。
  - before_llm 返回脱敏文本; after_llm 用同一 session_id 还原占位符。
  - 每次调用均写入结构化 JSONL 日志 (记录发出/接收的原始与转换后内容)。

环境变量:
  PII_DSH_DB_PATH    覆盖映射库路径
  PII_DSH_LOG_PATH   覆盖日志路径 (设为 "0" 关闭日志)
  PII_DSH_WHITELIST  白名单文件路径 (每行一个关键词, 命中的区域不脱敏)
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import os
from pathlib import Path
from typing import Tuple

from .engine import PresidioPIIEngine
from .journal import JsonlJournal

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_DB = _REPO_ROOT / ".pii_presidio_store" / "sessions.db"
_DEFAULT_LOG = _REPO_ROOT / ".pii_presidio_store" / "hook_log.jsonl"

_ENGINE: PresidioPIIEngine | None = None
_JOURNAL: JsonlJournal | None = None


def _db_path() -> Path:
    return Path(os.environ.get("PII_DSH_DB_PATH", _DEFAULT_DB))


def _whitelist() -> list:
    """从 PII_DSH_WHITELIST 指定的文件读取白名单 (每行一个词, # 注释)。"""
    raw = os.environ.get("PII_DSH_WHITELIST")
    if not raw:
        return []
    fp = Path(raw)
    if not fp.exists():
        return []
    return [ln.strip() for ln in fp.read_text(encoding="utf-8-sig").splitlines()
            if ln.strip() and not ln.strip().startswith("#")]


def _get_engine() -> PresidioPIIEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = PresidioPIIEngine(db_path=_db_path(), whitelist=_whitelist())
    return _ENGINE


def get_journal() -> JsonlJournal | None:
    """获取流程日志器; 环境变量 PII_DSH_LOG_PATH=0 时关闭。"""
    global _JOURNAL
    if _JOURNAL is None:
        raw = os.environ.get("PII_DSH_LOG_PATH", str(_DEFAULT_LOG))
        _JOURNAL = None if raw == "0" else JsonlJournal(raw)
    return _JOURNAL


def reset_singleton() -> None:
    """测试辅助: 清空引擎/日志单例 (环境变量变更后调用)。"""
    global _ENGINE, _JOURNAL
    _ENGINE = None
    _JOURNAL = None


def session_id(conversation_id: str | None) -> str:
    if conversation_id:
        return hashlib.sha1(conversation_id.encode("utf-8")).hexdigest()[:12]
    today = _dt.date.today().isoformat()
    return "daily-" + hashlib.sha1(today.encode("utf-8")).hexdigest()[:8]


def _entity_counts(placeholders: dict) -> dict:
    counts: dict = {}
    for ph in placeholders:
        ptype = ph.strip("⟦⟧").split(":")[1]
        counts[ptype] = counts.get(ptype, 0) + 1
    return counts


def before_llm(prompt: str, conversation_id: str | None = None,
               doc_id: str = "prompt") -> str:
    """发送给 LLM 之前调用: 脱敏并登记映射。返回脱敏后的文本。"""
    engine = _get_engine()
    sid = session_id(conversation_id)
    rd = engine.redact(prompt, sid, doc_id)
    journal = get_journal()
    if journal:
        journal.record("before_llm", conversation_id=conversation_id,
                       session_id=sid, doc_id=doc_id,
                       raw=prompt, transformed=rd.text,
                       n_replaced=rd.n_replaced,
                       entities=_entity_counts(rd.restored))
    return rd.text


def after_llm(response: str, conversation_id: str | None = None,
              doc_id: str = "prompt") -> Tuple[str, dict]:
    """LLM 响应返回后调用: 还原占位符。

    返回 (还原后文本, 统计字典)。DSH 若只接受单返回值, 取 [0] 即可。
    """
    engine = _get_engine()
    sid = session_id(conversation_id)
    rs = engine.restore(response, sid, doc_id)
    stats = {"n_restored": len(rs.restored), "n_unrestored": len(rs.unrestored)}
    journal = get_journal()
    if journal:
        journal.record("after_llm", conversation_id=conversation_id,
                       session_id=sid, doc_id=doc_id,
                       raw=response, transformed=rs.text, **stats)
    return rs.text, stats
