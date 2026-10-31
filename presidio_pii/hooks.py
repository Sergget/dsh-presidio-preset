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
  PII_DSH_CUSTOM_RULES  自定义规则文件 (分号分隔多个, .json=正则模板, .py=代码规则)
  PII_DSH_PRESET     覆盖 preset.json 路径

配置优先级: 环境变量 > preset.json 的 config 段 > 内置默认值。
preset.json 支持 db_path / whitelist_path / custom_rules_path 三个字段,
相对路径按仓库根目录解析。
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Tuple

from .engine import PresidioPIIEngine
from .journal import JsonlJournal

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_DB = _REPO_ROOT / ".pii_presidio_store" / "sessions.db"
_DEFAULT_LOG = _REPO_ROOT / ".pii_presidio_store" / "hook_log.jsonl"
_DEFAULT_PRESET = _REPO_ROOT / ".agent-presets" / "presidio-pii" / "preset.json"

_ENGINE: PresidioPIIEngine | None = None
_JOURNAL: JsonlJournal | None = None


def _preset_file() -> Path:
    return Path(os.environ.get("PII_DSH_PRESET", str(_DEFAULT_PRESET)))


def _preset_config() -> dict:
    """读取 DSH preset.json 的 config 段 (路径可用 PII_DSH_PRESET 覆盖)。

    环境变量优先级高于 preset 配置; preset 文件缺失或损坏时返回空字典,
    不影响环境变量与默认值生效。
    """
    fp = _preset_file()
    if not fp.exists():
        return {}
    try:
        data = json.loads(fp.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        print(f"[pii] preset 配置读取失败 ({fp}): {exc}", file=sys.stderr)
        return {}
    cfg = data.get("config")
    return cfg if isinstance(cfg, dict) else {}


def _preset_path(key: str) -> str | None:
    """取 preset 配置中的路径字段。

    相对路径优先按仓库根目录解析 (与默认 db_path 一致), 不存在时再按
    preset.json 所在目录解析 (支持把规则文件与 preset 放一起)。
    """
    value = _preset_config().get(key)
    if not value:
        return None
    p = Path(value)
    if p.is_absolute():
        return str(p)
    candidates = [_REPO_ROOT / p, _preset_file().parent / p]
    return str(next((c for c in candidates if c.exists()), candidates[0]))


def _db_path() -> Path:
    return Path(os.environ.get("PII_DSH_DB_PATH")
                or _preset_path("db_path") or _DEFAULT_DB)


def _whitelist_file() -> str | None:
    return os.environ.get("PII_DSH_WHITELIST") or _preset_path("whitelist_path")


def _custom_rules_spec() -> str | None:
    return (os.environ.get("PII_DSH_CUSTOM_RULES")
            or _preset_path("custom_rules_path"))


def _whitelist() -> list:
    """从白名单文件读取关键词 (每行一个词, # 注释)。"""
    raw = _whitelist_file()
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
        # 自定义规则来源已在此处合并 (env > preset), 显式传入空列表以避免重复加载
        from .custom_rules import load_custom_rules
        _ENGINE = PresidioPIIEngine(db_path=_db_path(), whitelist=_whitelist(),
                                    custom_rules=load_custom_rules(_custom_rules_spec()))
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
