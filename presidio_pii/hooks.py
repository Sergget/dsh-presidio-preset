"""DSH 钩子实现: before_llm / after_llm + 结构化流程日志。

会话语义:
  - session_id 由 conversation_id 派生 (稳定哈希), 同一会话多轮共享还原映射表;
    未传入时按日期派生, 同一天内共享。
  - before_llm 返回脱敏文本; after_llm 用同一 session_id 还原占位符。
  - 每次调用均写入结构化 JSONL 日志, 只记元数据 (实体类型/数量、内容指纹哈希),
    **不记录原文或还原后文本**; 旧字段 raw/transformed 已移除。

环境变量:
  PII_DSH_DB_PATH    覆盖映射库路径
  PII_DSH_LOG_PATH   覆盖日志路径 (设为 "0" 关闭日志)
  PII_DSH_LOG_MAX_BYTES  日志轮转上限 (字节, 默认 10 MB; 0 表示不限额)
  PII_DSH_WHITELIST  白名单文件路径 (每行一个关键词, 命中的区域不脱敏)
  PII_DSH_CUSTOM_RULES  自定义规则文件 (分号分隔多个, .json=正则模板, .py=代码规则)
  PII_DSH_RULES_RELOAD  规则热更新检查间隔 (秒, 默认 1; 0/off 关闭自动检查)
  PII_DSH_PRESET     覆盖 preset.json 路径

配置优先级: 环境变量 > preset.json 的 config 段 > 内置默认值。
preset.json 支持 db_path / whitelist_path / custom_rules_path /
rules_reload_interval 四个字段, 相对路径按仓库根目录解析。
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
from .journal import DEFAULT_MAX_BYTES, JsonlJournal

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


def _parse_interval(raw, default: float = 1.0) -> float:
    """解析热更新间隔: 秒数, 0/off/false 表示关闭自动检查。"""
    if raw is None:
        return default
    if isinstance(raw, bool):
        return default if raw else 0.0
    if isinstance(raw, (int, float)):
        return max(0.0, float(raw))
    text = str(raw).strip().lower()
    if not text:
        return default
    if text in ("0", "off", "false", "no", "none"):
        return 0.0
    try:
        return max(0.0, float(text))
    except ValueError:
        print(f"[pii] 无法解析规则热更新间隔 {raw!r}, 使用默认 {default}s",
              file=sys.stderr)
        return default


def _rules_reload_interval() -> float:
    """规则热更新检查间隔: 环境变量 > preset 配置 > 默认 1 秒。"""
    raw = os.environ.get("PII_DSH_RULES_RELOAD")
    if raw is None:
        raw = _preset_config().get("rules_reload_interval")
    return _parse_interval(raw)


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
        # 传规则来源字符串而非已加载列表, 让引擎能按文件签名热更新;
        # 来源已在此处合并 (env > preset)
        _ENGINE = PresidioPIIEngine(
            db_path=_db_path(), whitelist=_whitelist(),
            custom_rules=_custom_rules_spec(),
            rules_check_interval=_rules_reload_interval())
    return _ENGINE


def reload_rules(force: bool = True) -> int:
    """显式重载自定义规则, 返回当前规则条数。

    agent 改完规则文件后可立即调用; force=False 时仍受检查间隔节流。
    """
    return _get_engine().reload_custom_rules(force=force)


def get_journal() -> JsonlJournal | None:
    """获取流程日志器; 环境变量 PII_DSH_LOG_PATH=0 时关闭。"""
    global _JOURNAL
    if _JOURNAL is None:
        raw = os.environ.get("PII_DSH_LOG_PATH", str(_DEFAULT_LOG))
        _JOURNAL = None if raw == "0" else JsonlJournal(raw, max_bytes=_log_max_bytes())
    return _JOURNAL


def _log_max_bytes() -> int:
    """日志轮转上限: 环境变量 PII_DSH_LOG_MAX_BYTES, 默认 10 MB, 0=不限额。"""
    raw = (os.environ.get("PII_DSH_LOG_MAX_BYTES") or "").strip()
    if not raw:
        return DEFAULT_MAX_BYTES
    try:
        return max(0, int(raw))
    except ValueError:
        print(f"[pii] 无法解析日志上限 {raw!r}, 使用默认 {DEFAULT_MAX_BYTES}",
              file=sys.stderr)
        return DEFAULT_MAX_BYTES


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


def _fingerprint(text: str) -> str:
    """内容指纹: 单向 SHA256 前 16 位, 不足以还原原文。"""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _id_fingerprint(value: str | None) -> str | None:
    """会话/文档标识指纹; 文件名、会话号可能含 PII, 日志只留哈希。"""
    if not value:
        return None
    return hashlib.sha1(value.encode("utf-8")).hexdigest()[:12]


def before_llm(prompt: str, conversation_id: str | None = None,
               doc_id: str = "prompt") -> str:
    """发送给 LLM 之前调用: 脱敏并登记映射。返回脱敏后的文本。"""
    engine = _get_engine()
    sid = session_id(conversation_id)
    rd = engine.redact(prompt, sid, doc_id)
    journal = get_journal()
    if journal:
        journal.record("before_llm",
                       conv_sha1=_id_fingerprint(conversation_id),
                       session_id=sid,
                       doc_sha1=_id_fingerprint(doc_id),
                       n_replaced=rd.n_replaced,
                       entities=rd.entity_counts,
                       redacted_sha256=_fingerprint(rd.text),
                       chars=len(prompt))
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
        journal.record("after_llm",
                       conv_sha1=_id_fingerprint(conversation_id),
                       session_id=sid,
                       doc_sha1=_id_fingerprint(doc_id),
                       n_restored=stats["n_restored"],
                       n_unrestored=stats["n_unrestored"],
                       entities=_entity_counts(rs.restored),
                       response_sha256=_fingerprint(response),
                       chars=len(response))
    return rs.text, stats
